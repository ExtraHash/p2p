package p2p

import (
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	uuid "github.com/satori/go.uuid"
	"github.com/vmihailenco/msgpack"
)

// ActiveConnection is a current websocket connection
type ActiveConnection struct {
	conn    *websocket.Conn
	host    string
	authed  bool
	alive   bool
	vID     uuid.UUID
	signkey ed25519.PublicKey
	sealKey []byte
	mu      sync.Mutex
}

func (ac *ActiveConnection) prune(cList *[]*ActiveConnection) {
	currentList := *cList
	for i, c := range currentList {
		if c == ac {
			c.conn.Close()
			currentList[i] = currentList[len(currentList)-1] // Copy last element to index i.
			currentList[len(currentList)-1] = nil            // Erase last element (write zero value).
			currentList = currentList[:len(currentList)-1]
			break
		}
	}
	*cList = currentList
}

func (ac *ActiveConnection) send(msg []byte) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.conn.WriteMessage(2, msg)
}

func (ac *ActiveConnection) authenticate() {
	b, err := msgpack.Marshal(&challenge{Type: "challenge", Challenge: ac.vID.String()})
	if err != nil {
		panic(err)
	}
	ac.send(b)

	time.Sleep(3 * time.Second)

	if !ac.authed {
		log.Warning("Peer " + ac.host + " did not authorize in time, closing connection.")
		ac.conn.Close()
	}
}

func (ac *ActiveConnection) pong() {
	b, err := msgpack.Marshal(&message{Type: "pong"})
	if err != nil {
		panic(err)
	}

	ac.send(b)
}

func (ac *ActiveConnection) ping() {
	for {
		if !ac.alive {
			ac.conn.Close()
			break
		}

		ac.alive = false
		b, err := msgpack.Marshal(&message{Type: "ping"})
		if err != nil {
			panic(err)
		}
		ac.send(b)

		time.Sleep(5 * time.Second)
	}
}
