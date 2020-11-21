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
	clientReceived lockList
	readMu         sync.Mutex
}

func (cm *clientManager) initialize(core *core) {
	cm.core = core
	cm.initSelfClient()

	go cm.takePeers()
	go cm.findPeers()
	cm.pruneList()
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
	cm.addToCoClientList(&selfClient)
}

func (cm *clientManager) propagate(msg []byte, messageID string) {
	for _, consumer := range cm.clients {
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
				log.Debug("Peer unavailable." + peer.toString(false))
				log.Error(err)
				continue
			}

			peerBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				log.Error(err)
				return
			}

			newList := []Peer{}
			json.Unmarshal(peerBody, &newList)

			for _, newPeer := range newList {
				checkPeer := Peer{}
				cm.core.db.db.Find(&checkPeer, "sign_key = ?", peer.SignKey)
				if checkPeer == (Peer{}) {
					cm.core.db.db.Create(&newPeer)
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
			cm.core.db.db.Take(&peer)
			if !cm.inClientList(peer) {
				log.Debug("Attempting to dial " + peer.toString(false))
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
		finished := false
		for {
			for i, c := range cm.clients {
				if c.failed {
					cm.clients = append(cm.clients[:i], cm.clients[i+1:]...)
					break
				}
				if i == len(cm.clients)-1 {
					finished = true
				}
			}
			if finished {
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
