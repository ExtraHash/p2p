package p2p

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
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
			log.Debug("Requesting peerlist from " + peer.toString(false))
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
				log.Debug("Checking if peer is new: " + newPeer.toString(false) + " " + newPeer.SignKey)
				checkPeer := Peer{}
				cm.core.db.db.Find(&checkPeer, "sign_key = ?", newPeer.SignKey)
				if checkPeer == (Peer{}) {
					log.Debug("New peer found: " + newPeer.toString(false))
					cm.core.db.db.Create(&newPeer)
				} else {
					log.Debug("Peer is not new: " + newPeer.toString(false))
				}
			}
		}
		time.Sleep(3 * time.Minute)
	}

}

func (cm *clientManager) takePeers() {
	for {
		log.Debug("Currently have " + strconv.Itoa(len(cm.clients)) + " on client list.")
		if len(cm.clients) < 8 {
			peer := Peer{}
			cm.core.db.db.Take(&peer)
			log.Debug("Took peer " + peer.toString(false))
			if !cm.inClientList(peer) {
				log.Debug("Not in list, attempting to dial " + peer.toString(false))
				c := client{}
				go c.initialize(cm.core, &peer, &cm.clientReceived, &cm.readMu)
				cm.addToCoClientList(&c)
			} else {
				log.Debug("Didn't add because already in list: " + peer.toString(false))
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func (cm *clientManager) pruneList() {

	for {
		finished := false
		for {
			cm.clientMu.Lock()
			for i, c := range cm.clients {
				if c.failed {
					log.Debug("Removing from peer list: " + c.peer.toString(false))
					cm.clients = append(cm.clients[:i], cm.clients[i+1:]...)
					break
				}
				if i == len(cm.clients)-1 {
					finished = true
				}
			}
			if finished {
				cm.clientMu.Unlock()
				break
			}
		}
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
