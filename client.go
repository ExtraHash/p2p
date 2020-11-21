package p2p

import (
	"crypto/ed25519"
	"strconv"
	"sync"
	"time"

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
	core     *core
	received *lockList
	readMu   *sync.Mutex

	peer *Peer
	conn *websocket.Conn

	serverInfo   infoRes
	authorized   bool
	connecting   bool
	failed       bool
	isSelfClient bool
	pingTime     time.Duration

	mu sync.Mutex
}

func (client *client) initialize(core *core, peer *Peer, received *lockList, readMu *sync.Mutex, selfClient bool) {
	client.core = core
	client.connecting = true
	client.readMu = readMu
	client.authorized = false
	client.failed = false
	client.received = received
	client.peer = peer
	client.isSelfClient = selfClient
	client.handshake()
}

func (client *client) handshake() {

	httpClient := http.Client{
		Timeout: 1 * time.Second,
	}

	startPing := time.Now()
	infoURL := url.URL{Scheme: "http", Host: client.toString(), Path: "/info"}
	iRes, err := httpClient.Get(infoURL.String())
	if err != nil {
		client.fail()
		return
	}
	client.pingTime = time.Since(startPing)

	infoBody, err := ioutil.ReadAll(iRes.Body)
	if err != nil {
		client.fail()
		return
	}

	info := infoRes{}
	json.Unmarshal(infoBody, &info)

	client.serverInfo = info

	u := url.URL{Scheme: "ws", Host: client.toString(), Path: "/socket"}

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		client.fail()
		return
	}
	client.conn = c
	go client.listen()
}

func (client *client) toString() string {
	return client.peer.Host + ":" + strconv.Itoa(client.peer.Port)
}

func (client *client) listen() {
	for {
		_, rawMessage, err := client.conn.ReadMessage()
		if err != nil {
			client.fail()
			return
		}
		if client.core.config.LogLevel > 1 {
			log.Infof(colors.boldCyan+"RECV"+colors.reset+" %s", rawMessage)
		}

		msg := message{}
		err = msgpack.Unmarshal(rawMessage, &msg)
		if err != nil {
			client.fail()
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
			log.Info(colors.boldGreen+"AUTH"+colors.reset, "Logged in to "+client.peer.toString(false))
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
		client.fail()
	}

	bNonce, err := hex.DecodeString(nonce)
	if err != nil {
		client.fail()
	}

	bTheirKey, err := hex.DecodeString(theirKey)

	unsealed, success := box.Open(nil, bMes, nonceSliceConvert(bNonce), keySliceConvert(bTheirKey), &client.core.keys.sealKeys.Priv)
	if !success {
		log.Warning("Decryption failed from " + client.toString())
		client.fail()
	}
	return unsealed, success
}

func (client *client) fail() {
	if client.conn != nil {
		client.conn.Close()
	}
	client.failed = true
	client.connecting = false
	client.authorized = false
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
			client.core.clientManager.propagate(unsealed, broadcast.MessageID)
		} else {
			if client.core.config.LogLevel > 1 {
				log.Info(colors.boldMagenta+"CAST"+colors.reset, broadcast.MessageID)
			}
		}
	}
}

func (client *client) emit(data []byte) {
	*client.core.messages <- data
}

func (client *client) response(msg []byte) {
	challenge := challenge{}
	msgpack.Unmarshal(msg, &challenge)

	signed := ed25519.Sign(client.core.keys.signKeys.Priv, []byte(challenge.Challenge))

	response := response{
		Type:      "response",
		Signed:    hex.EncodeToString(signed),
		SignKey:   hex.EncodeToString(client.core.keys.signKeys.Pub),
		SealKey:   hex.EncodeToString(sealToString(client.core.keys.sealKeys.Pub)),
		Port:      client.core.config.Port,
		NetworkID: client.core.config.NetworkID,
	}

	bMes, err := msgpack.Marshal(response)
	if err != nil {
		log.Error(err)
		client.fail()
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
		client.fail()
		return
	}
	if client.core.config.LogLevel > 1 {
		log.Infof(colors.boldCyan+"SEND"+colors.reset+" %s", msg)
	}
}

func (client *client) ping() {
	pong := message{Type: "pong"}
	bMes, _ := msgpack.Marshal(pong)
	client.send(bMes)
}
