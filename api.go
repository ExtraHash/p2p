package p2p

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	uuid "github.com/satori/go.uuid"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/nacl/box"
)

type api struct {
	core *core

	router *mux.Router
	ac     []*ActiveConnection
	acMu   sync.Mutex

	serverReceived lockList
}

func (a *api) getPeerList() []Peer {
	a.acMu.Lock()
	defer a.acMu.Unlock()

	peerList := []Peer{}

	for _, conn := range a.ac {
		if conn.authed {
			peerList = append(peerList, conn.dbEntry)
		}
	}

	return []Peer{}
}

func (a *api) whisper(msg []byte, pubKey string, messageID string) bool {
	for _, connection := range a.ac {
		if hex.EncodeToString(connection.signkey) == pubKey {
			nonce := makeNonce()
			secret := box.Seal(nil, msg, nonce.bytes, keySliceConvert(connection.sealKey), &a.core.keys.sealKeys.Priv)
			whisper := broadcast{
				Type:      "whisper",
				Secret:    hex.EncodeToString(secret),
				Nonce:     nonce.str,
				MessageID: messageID,
			}
			byteWhisper, err := msgpack.Marshal(whisper)
			if err != nil {
				log.Error(err)
				return false
			}
			connection.send(byteWhisper)
			return true
		}
	}
	return false
}

func (a *api) initialize(core *core) {
	a.core = core
	a.ac = []*ActiveConnection{}
	a.getRouter()
}

// Run starts the server.
func (a *api) run() error {
	log.Info(colors.boldYellow+"HTTP"+colors.reset, "Starting API on port "+strconv.Itoa(a.core.config.Port)+".")
	err := http.ListenAndServe(":"+strconv.Itoa(a.core.config.Port),
		handlers.CORS(handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"}),
			handlers.AllowedMethods([]string{"GET", "POST", "PUT", "HEAD", "OPTIONS", "PATCH"}),
			handlers.AllowedOrigins([]string{"*"}))(a.router))
	return err
}

func (a *api) getRouter() {
	// initialize router
	a.router = mux.NewRouter()
	a.router.Handle("/", a.HomeHandler()).Methods("GET")
	a.router.Handle("/info", a.InfoHandler()).Methods("GET")
	a.router.Handle("/peers", a.PeerHandler()).Methods("GET", "POST")
	a.router.Handle("/socket", a.SocketHandler()).Methods("GET")
}

// PeerHandler handles the status endpoint.
func (a *api) PeerHandler() http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		log.Info(colors.boldYellow+"HTTP"+colors.reset, req.Method, req.URL, GetIP(req))

		switch req.Method {
		case "GET":
			peerList := a.core.db.getPeerList()
			byteRes, err := json.Marshal(peerList)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
			}

			res.Header().Set("Content-Type", "application/json")
			res.WriteHeader(http.StatusOK)
			res.Write(byteRes)
		}

	})
}

// InfoHandler handles the info endpoint.
func (a *api) InfoHandler() http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		log.Info(colors.boldYellow+"HTTP"+colors.reset, req.Method, req.URL, GetIP(req))

		infoRes := infoRes{
			PubSignKey: hex.EncodeToString(a.core.keys.signKeys.Pub),
			PubSealKey: hex.EncodeToString(a.core.keys.sealKeys.Pub[:]),
			Version:    version,
		}

		byteRes, err := json.Marshal(&infoRes)
		if err != nil {
			res.WriteHeader(http.StatusInternalServerError)
		}

		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		res.Write(byteRes)
	})
}

// HomeHandler handles the server homepage.
func (a *api) HomeHandler() http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		log.Info(colors.boldYellow+"HTTP"+colors.reset, req.Method, req.URL, GetIP(req))

		res.WriteHeader(http.StatusOK)

		res.Write([]byte("<!DOCTYPE html>"))
		res.Write([]byte("<html>"))
		res.Write([]byte("<style> body { width: 50em; margin: 0 auto; font-family: monospace; } ul { list-style: none } </style>"))
		res.Write([]byte("<body>"))
		res.Write([]byte("<h1>extrap2p</h1>"))
		res.Write([]byte("<p>If you can see this, the node is running.</p>"))
		res.Write([]byte("<h2>Server Information</h2>"))
		res.Write([]byte("<ul>"))
		res.Write([]byte("<li>Version: &nbsp;&nbsp;&nbsp;&nbsp;" + version + " </li>"))
		res.Write([]byte("<li>Hostname: &nbsp;&nbsp;&nbsp;" + req.Host + "</li>"))
		res.Write([]byte("</ul>"))
		res.Write([]byte("<p>© LogicBite LLC 2019-2020. See included LICENSE for details.</p>"))
		res.Write([]byte("</body>"))
		res.Write([]byte("</html>"))
	})
}

// SocketHandler handles the websocket connection messages and responses.
func (a *api) SocketHandler() http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		log.Info(colors.boldYellow+"HTTP"+colors.reset, req.Method, req.URL, GetIP(req))

		var upgrader = websocket.Upgrader{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			EnableCompression: true,
		}

		upgrader.CheckOrigin = func(req *http.Request) bool { return true }

		conn, err := upgrader.Upgrade(res, req, nil)
		if err != nil {
			log.Warning(err)
			return
		}

		conn.SetReadLimit(3000000)

		ac := ActiveConnection{
			conn:   conn,
			host:   GetIP(req),
			alive:  true,
			authed: false,
			vID:    uuid.NewV4(),
		}

		a.acMu.Lock()
		a.ac = append(a.ac, &ac)
		a.acMu.Unlock()

		log.Info(colors.boldYellow+"HTTP"+colors.reset, "UPGRADED", GetIP(req))

		go ac.authenticate()
		go ac.ping()

		for {
			_, data, err := conn.ReadMessage()

			if err != nil {
				log.Error(err)
				conn.Close()
				a.removeConnection(&ac)
				break
			}

			msg := message{}
			err = msgpack.Unmarshal(data, &msg)

			if err != nil {
				log.Error(err)
				conn.Close()
				break
			}

			switch msg.Type {
			case "response":
				response := response{}
				err = msgpack.Unmarshal(data, &response)

				if response.NetworkID != a.core.config.NetworkID {
					log.Warning(response.NetworkID, a.core.config.NetworkID)
					log.Warning("Peer has incorrect network ID. Terminating connection.")
					conn.Close()
					a.removeConnection(&ac)
				}

				peerSignKey, err := hex.DecodeString(response.SignKey)
				if err != nil {
					log.Error(err)
					break
				}
				peerSealKey, err := hex.DecodeString(response.SealKey)
				if err != nil {
					log.Error(err)
					break
				}
				signed, err := hex.DecodeString(response.Signed)
				if err != nil {
					log.Error(err)
					break
				}

				if ed25519.Verify(peerSignKey, []byte(ac.vID.String()), signed) {
					ac.authed = true
					ac.signkey = peerSignKey
					ac.sealKey = peerSealKey

					byteMessage, _ := msgpack.Marshal(message{Type: "authorized"})
					ac.send(byteMessage)

					baseIP, _ := splitIP(GetIP(req))
					if baseIP != "127.0.0.1" {
						dbEntry := Peer{}
						a.core.db.db.Find(&dbEntry, "sign_key = ?", response.SignKey)
						if dbEntry == (Peer{}) {
							newPeer := Peer{
								Host:      baseIP,
								Port:      response.Port,
								SignKey:   response.SignKey,
								SealKey:   response.SealKey,
								LastSeen:  time.Now(),
								Acessible: false,
								Direction: "in",
							}
							a.core.db.db.Create(&newPeer)
							dbEntry = newPeer
							log.Info("Api discovered new inbound peer: " + newPeer.toString(false) + " " + newPeer.SignKey)
						} else {
							dbEntry.Direction = "in"
							a.core.db.db.Model(&Peer{}).Where("sign_key = ?", dbEntry.SignKey).Updates(Peer{SealKey: response.SealKey, LastSeen: time.Now()})
						}
						if dbEntry.online() {
							a.core.db.db.Model(&Peer{}).Where("sign_key = ?", dbEntry.SignKey).Updates(Peer{Acessible: true})
						}
					}
				} else {
					log.Warning("Client " + GetIP(req) + " invalid auth signature.")
					ac.conn.Close()
					break
				}

			case "ping":
				ac.pong()
			case "pong":
				ac.alive = true
			case "broadcast":
				if !ac.authed {
					log.Warning("Peer attempted to use broadcast without being authed.")
					break
				}

				broadcast := broadcast{}
				err = msgpack.Unmarshal(data, &broadcast)

				if err != nil {
					log.Error(err)
					break
				}

				crypt, err := hex.DecodeString(broadcast.Secret)
				if err != nil {
					log.Error(err)
					break
				}

				nonceS, err := hex.DecodeString(broadcast.Nonce)
				if err != nil {
					log.Error(err)
					break
				}
				var nonceA [24]byte
				copy(nonceA[:], nonceS[:24])

				var theirPublicKey [32]byte
				copy(theirPublicKey[:], ac.sealKey[:32])

				unsealed, success := box.Open(nil, crypt, &nonceA, &theirPublicKey, &a.core.keys.sealKeys.Priv)
				if success {
					if !a.serverReceived.contains([]byte(broadcast.MessageID)) {
						a.serverReceived.push([]byte(broadcast.MessageID))
						a.emitBroadcast(unsealed, broadcast.MessageID)
					}
				} else {
					log.Warning("Decryption failed.")
				}
			default:
				log.Warning("Unsupported message: ", msg.Type)
			}

		}
	})
}

func (a *api) removeConnection(connection *ActiveConnection) {
	a.acMu.Lock()
	defer a.acMu.Unlock()
	for i, c := range a.ac {
		if c == connection {
			a.ac[i] = a.ac[len(a.ac)-1] // Copy last element to index i.
			a.ac[len(a.ac)-1] = nil     // Erase last element (write zero value).
			a.ac = a.ac[:len(a.ac)-1]
			break
		}
	}
}

func (a *api) emitBroadcast(message []byte, messageID string) {
	for _, ac := range a.ac {
		if ac.conn == nil {
			continue
		}
		if ac.authed {
			nonce := makeNonce()
			secret := box.Seal(nil, message, nonce.bytes, keySliceConvert(ac.sealKey), &a.core.keys.sealKeys.Priv)
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
				ac.send(byteCast)
			}
		}
	}
}
