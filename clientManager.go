package p2p

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/nacl/box"
)

// clientManager handles active outgoing clients.
type clientManager struct {
	core *core

	clientMu       sync.Mutex
	clients        []*client
	selfClient     *client
	clientReceived lockList
	readMu         sync.Mutex
}

func (cm *clientManager) initialize(core *core) {
	cm.core = core
	cm.initSelfClient()

	go cm.takePeers()
	go cm.findPeers()
	go cm.pruneList()
	go cm.logging()
}

func (cm *clientManager) logging() {
	for {
		time.Sleep(2 * time.Minute)
		log.Debug("║ Current peers:")
		for _, client := range cm.clients {
			log.Debug("║ " + client.toString())
		}
	}
}

func (cm *clientManager) initSelfClient() {
	selfPeer := Peer{
		Host:    "127.0.0.1",
		Port:    cm.core.config.Port,
		SignKey: hex.EncodeToString(cm.core.keys.signKeys.Pub),
		SealKey: hex.EncodeToString(cm.core.keys.sealKeys.Pub[:]),
	}
	selfClient := client{}
	selfClient.initialize(cm.core, &selfPeer, &cm.clientReceived, &cm.readMu)
	cm.selfClient = &selfClient
}

func (cm *clientManager) propagate(msg []byte, messageID string) {
	for _, consumer := range append(cm.clients, cm.selfClient) {
		if consumer.conn == nil {
			continue
		}
		byteKey, err := hex.DecodeString(consumer.serverInfo.PubSealKey)
		if err != nil {
			log.Error(err)
			return
		}
		nonce := makeNonce()
		secret := box.Seal(nil, msg, nonce.bytes, keySliceConvert(byteKey), &cm.core.keys.sealKeys.Priv)
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

func (cm *clientManager) findPeers() {
	for {
		peerList := cm.core.db.getPeerList()
		for _, peer := range peerList {
			peerURL := url.URL{Scheme: "http", Host: peer.toString(false), Path: "/peers"}

			res, err := http.Get(peerURL.String())
			if err != nil {
				continue
			}

			peerBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				continue
			}

			newList := []Peer{}
			json.Unmarshal(peerBody, &newList)

			for _, newPeer := range newList {
				checkPeer := Peer{}
				cm.core.db.db.Find(&checkPeer, "sign_key = ?", newPeer.SignKey)
				if checkPeer == (Peer{}) {
					cm.core.db.db.Create(&newPeer)
					log.Debug("Discovered peer: " + newPeer.toString(false))
				}
			}
		}
		time.Sleep(3 * time.Minute)
	}

}

func (cm *clientManager) takePeers() {
	for {
		if len(cm.clients) < 8 {
			peer := Peer{}
			cm.core.db.db.Raw("SELECT * FROM peers ORDER BY RANDOM() LIMIT 1;").Scan(&peer)
			if !cm.inClientList(peer) {
				c := client{}
				go c.initialize(cm.core, &peer, &cm.clientReceived, &cm.readMu)
				cm.addToCoClientList(&c)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func (cm *clientManager) pruneList() {
	for {
		cm.clientMu.Lock()
		for i, c := range cm.clients {
			if c.failed {
				cm.clients = append(cm.clients[:i], cm.clients[i+1:]...)
				break
			}
		}
		cm.clientMu.Unlock()
		time.Sleep(5 * time.Second)
	}

}

func (cm *clientManager) addToCoClientList(newClient *client) {
	cm.clientMu.Lock()
	defer cm.clientMu.Unlock()
	cm.clients = append(cm.clients, newClient)
}

func (cm *clientManager) inClientList(peer Peer) bool {
	cm.clientMu.Lock()
	defer cm.clientMu.Unlock()
	for _, c := range cm.clients {
		if c.peer.SignKey == peer.SignKey {
			return true
		}
	}
	return false
}
