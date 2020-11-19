package p2p

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/nacl/box"
)

type clientList struct {
	consumers []*client
	mu        sync.Mutex
	maxLength int
	db        db
	api       *api
	keys      keys
	received  *lockList
	readMu    *sync.Mutex
	peerList  peerList
	config    NetworkConfig
	messages  *chan []byte
}

func (l *clientList) initialize(config NetworkConfig, maxLength int, db db, api *api, keys keys, received *lockList, readMu *sync.Mutex, messages *chan []byte) {
	l.db = db
	l.api = api
	l.keys = keys
	l.received = received
	l.readMu = readMu
	l.config = config
	l.messages = messages

	l.setMaxLength(maxLength)
	l.peerList.list = db.getPeerList()

	go l.scan()
	go l.connect()
}

func (l *clientList) createConsumer(peer Peer) {
	multiplier := math.Pow(2, float64(peer.FailCount))
	time.Sleep(time.Second*time.Duration(multiplier) - time.Second)
	newClient := client{}
	go newClient.initialize(l.config, peer, l.keys, l.api, l, l.received, l.db, l.readMu, l.messages)
}

func (l *clientList) connect() {
	for {
		for _, peer := range l.peerList.list {
			if !l.connectedTo(peer.SignKey) {
				l.createConsumer(peer)
			}
		}
		time.Sleep(time.Second * 5)
	}
}

func (l *clientList) scan() {
	for {
		for _, peer := range l.peerList.list {
			peerURL := url.URL{Scheme: "http", Host: peer.toString(false), Path: "/peers"}

			res, err := http.Get(peerURL.String())
			if err != nil {
				log.Error(err)
				l.peerList.remove(peer)
				return
			}

			peerBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				log.Error(err)
				l.peerList.remove(peer)
				return
			}

			newList := []Peer{}
			json.Unmarshal(peerBody, &newList)

			for _, p := range newList {
				if !l.peerList.contains(p) {
					if !l.peerList.contains(p) {
						log.Notice("Discovered a new peer: " + peer.toString(false))
						l.peerList.push(p)
					}
				}
			}
		}
		time.Sleep(3 * time.Minute)
	}

}

func (l *clientList) setMaxLength(length int) {
	l.maxLength = length
}

func (l *clientList) push(value *client) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consumers = append(l.consumers, value)

	if len(l.consumers) > l.maxLength {
		l.unshift()
	}
}

func (l *clientList) pop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consumers = l.consumers[:len(l.consumers)-1]
}

func (l *clientList) shift(value *client) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consumers = append([]*client{value}, l.consumers...)
	if len(l.consumers) > l.maxLength {
		l.pop()
	}
}

func (l *clientList) unshift() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consumers = l.consumers[1:]
}

func (l *clientList) contains(e *client) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range l.consumers {
		if a.peer.Host == e.peer.Host && a.peer.Port == e.peer.Port {
			return true
		}
	}
	return false
}

func (l *clientList) connectedTo(signKey string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range l.consumers {
		if a.peer.SignKey == signKey {
			return true
		}
	}
	return false
}

func (l *clientList) prune(client *client) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, c := range l.consumers {
		if c == client {
			c.conn.Close()
			l.consumers[i] = l.consumers[len(l.consumers)-1] // Copy last element to index i.
			l.consumers[len(l.consumers)-1] = nil            // Erase last element (write zero value).
			l.consumers = l.consumers[:len(l.consumers)-1]
			break
		}
	}
}

func (l *clientList) propagate(msg []byte, messageID string, privKey *[32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, consumer := range l.consumers {
		byteKey, err := hex.DecodeString(consumer.serverInfo.PubSealKey)
		if err != nil {
			log.Error(err)
			return
		}
		nonce := makeNonce()
		secret := box.Seal(nil, msg, nonce.bytes, keySliceConvert(byteKey), privKey)
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
