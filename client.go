package p2p

import (
	"crypto/ed25519"
	"strconv"
	"sync"

	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/nacl/box"
)

type client struct {
	conn          *websocket.Conn
	serverInfo    infoRes
	authorized    bool
	connecting    bool
	keys          keys
	peer          Peer
	received      *lockList
	api           *api
	activeClients *clientList
	mu            sync.Mutex
	readMu        *sync.Mutex
	db            db
	config        NetworkConfig
	messages      *chan []byte
}

func (client *client) initialize(config NetworkConfig, peer Peer, keys keys, api *api, activeClients *clientList, received *lockList, db db, readMu *sync.Mutex, messages *chan []byte) {
	client.connecting = true
	client.messages = messages
	client.readMu = readMu
	client.config = config
	client.authorized = false
	client.keys = keys
	client.api = api
	client.activeClients = activeClients
	client.received = received
	client.db = db
	client.peer = peer
	client.handshake()
}

func (client *client) handshake() {
	infoURL := url.URL{Scheme: "http", Host: client.toString(), Path: "/info"}

	iRes, err := http.Get(infoURL.String())
	if err != nil {
		log.Error(err)
		return
	}

	infoBody, err := ioutil.ReadAll(iRes.Body)
	if err != nil {
		log.Error(err)
		return
	}

	info := infoRes{}
	json.Unmarshal(infoBody, &info)

	client.serverInfo = info

	u := url.URL{Scheme: "ws", Host: client.toString(), Path: "/socket"}

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Error("dial:", err)
		return
	}
	client.conn = c
	go client.listen()
}

func (client *client) toString() string {
	return client.peer.Host + ":" + strconv.Itoa(client.peer.Port)
}

func (client *client) prune() {
	client.activeClients.prune(client)
}

func (client *client) listen() {
	for {
		_, rawMessage, err := client.conn.ReadMessage()
		if err != nil {
			log.Info("err:", err)
			client.prune()
			return
		}
		if client.config.LogLevel > 1 {
			log.Infof(colors.boldCyan+"RECV"+colors.reset+" %s", rawMessage)
		}

		msg := message{}
		err = msgpack.Unmarshal(rawMessage, &msg)
		if err != nil {
			log.Error(err)
			client.prune()
			return
		}
		switch msg.Type {
		case "ping":
			client.ping()
		case "pong":
			pass()
		case "challenge":
			if !client.authorized {
				client.response(rawMessage)
			}
		case "authorized":
			client.authorized = true
			client.connecting = false
			log.Info(colors.boldGreen+"AUTH"+colors.reset, client.peer.Host)
			client.activeClients.push(client)
			dbEntry := Peer{}
			client.db.db.Where("sign_key = ?", client.serverInfo.PubSignKey).Find(&dbEntry)
			// if the peer is not currently in database, store it
			if dbEntry == (Peer{}) && client.peer.Host != "127.0.0.1" {
				dbEntry := Peer{
					Host:      client.peer.Host,
					Port:      client.peer.Port,
					SignKey:   client.serverInfo.PubSignKey,
					SealKey:   client.serverInfo.PubSealKey,
					Connected: false,
				}
				client.db.db.Create(&dbEntry)
			}
		case "broadcast":
			client.parse(rawMessage)
		default:
			log.Warning("unknown message type: " + msg.Type)
		}
	}
}

func (client *client) decrypt(msg string, nonce string, theirKey string) ([]byte, bool) {
	bMes, err := hex.DecodeString(msg)
	if err != nil {
		panic(err)
	}

	bNonce, err := hex.DecodeString(nonce)
	if err != nil {
		panic(err)
	}

	bTheirKey, err := hex.DecodeString(theirKey)

	unsealed, success := box.Open(nil, bMes, nonceSliceConvert(bNonce), keySliceConvert(bTheirKey), &client.keys.sealKeys.Priv)
	if !success {
		panic("Decryption failed.")
	}
	return unsealed, success
}

func (client *client) parse(msg []byte) {
	client.readMu.Lock()
	defer client.readMu.Unlock()

	broadcast := broadcast{}
	msgpack.Unmarshal(msg, &broadcast)

	unsealed, decrypted := client.decrypt(broadcast.Secret, broadcast.Nonce, client.serverInfo.PubSealKey)
	if decrypted {
		if !client.received.contains([]byte(broadcast.MessageID)) {
			client.received.push([]byte(broadcast.MessageID))
			log.Info(colors.boldMagenta+"CAST"+colors.reset, colors.boldYellow+"***"+colors.reset, broadcast.MessageID)
			go client.emit(unsealed)
			client.propagate(unsealed, broadcast.MessageID)
		} else {
			if client.config.LogLevel > 1 {
				log.Info(colors.boldMagenta+"CAST"+colors.reset, broadcast.MessageID)
			}
		}
	}
}

func (client *client) emit(data []byte) {
	log.Debug("sending", data)
	*client.messages <- data
}

func (client *client) propagate(msg []byte, messageID string) {
	for _, consumer := range client.activeClients.consumers {
		byteKey, err := hex.DecodeString(consumer.serverInfo.PubSealKey)
		if err != nil {
			log.Error(err)
			return
		}
		nonce := makeNonce()
		secret := box.Seal(nil, msg, nonce.bytes, keySliceConvert(byteKey), &client.keys.sealKeys.Priv)
		broadcast := broadcast{
			Type:      "broadcast",
			Secret:    hex.EncodeToString(secret),
			Nonce:     nonce.str,
			MessageID: messageID,
		}
		byteCast, err := msgpack.Marshal(broadcast)
		if err != nil {
			log.Error(err)
		} else {
			consumer.send(byteCast)
		}
	}
}

func (client *client) response(msg []byte) {
	challenge := challenge{}
	msgpack.Unmarshal(msg, &challenge)

	signed := ed25519.Sign(client.keys.signKeys.Priv, []byte(challenge.Challenge))

	response := response{
		Type:      "response",
		Signed:    hex.EncodeToString(signed),
		SignKey:   hex.EncodeToString(client.keys.signKeys.Pub),
		SealKey:   hex.EncodeToString(sealToString(client.keys.sealKeys.Pub)),
		Port:      client.api.config.Port,
		NetworkID: client.config.NetworkID,
	}

	bMes, err := msgpack.Marshal(response)
	if err != nil {
		log.Error(err)
		return
	}

	client.send(bMes)
}

func (client *client) send(msg []byte) {
	client.mu.Lock()
	defer client.mu.Unlock()
	err := client.conn.WriteMessage(websocket.BinaryMessage, msg)
	if err != nil {
		log.Error(err)
		return
	}
	if client.config.LogLevel > 1 {
		log.Infof(colors.boldCyan+"SEND"+colors.reset+" %s", msg)
	}
}

func (client *client) ping() {
	pong := message{Type: "pong"}
	bMes, _ := msgpack.Marshal(pong)
	client.send(bMes)
}
