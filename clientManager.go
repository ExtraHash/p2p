package p2p

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/nacl/box"
)

// clientManager handles active outgoing clients.
type clientManager struct {
	core *core

	clientMu       sync.Mutex
	clients        *[]*client
	clientReceived lockList
	readMu         sync.Mutex
}

func (cm *clientManager) initialize(core *core) {
	cm.core = core
	cm.clients = &[]*client{}

	go cm.takePeers()
	go cm.findPeers()
	go cm.pruneList()
}

func (cm *clientManager) getPeerList() []Peer {
	cm.clientMu.Lock()
	defer cm.clientMu.Unlock()
	if cm.clients == nil {
		return []Peer{}
	}

	peers := []Peer{}
	for _, client := range *cm.clients {
		if client == nil {
			continue
		}
		if client.authorized {
			*&client.peer.Direction = "out"
			peers = append(peers, *client.peer)
		}
	}
	return peers
}

func (cm *clientManager) whisper(msg []byte, pubKey string, messageID string) bool {
	if cm.clients == nil {
		return false
	}
	for _, consumer := range *cm.clients {
		if consumer == nil {
			continue
		}
		if consumer.conn == nil {
			continue
		}
		fmt.Println(consumer.peer.SignKey)
		if consumer.peer.SignKey == pubKey {
			byteKey, err := hex.DecodeString(consumer.serverInfo.PubSealKey)
			if err != nil {
				log.Error(err)
				return false
			}
			nonce := makeNonce()
			secret := box.Seal(nil, msg, nonce.bytes, keySliceConvert(byteKey), &cm.core.keys.sealKeys.Priv)
			broadcast := broadcast{
				Type:      "whisper",
				Secret:    hex.EncodeToString(secret),
				Nonce:     nonce.str,
				MessageID: messageID,
			}
			byteCast, err := msgpack.Marshal(broadcast)
			if err != nil {
				log.Error(err)
				return false
			}
			consumer.send(byteCast)
			return true
		}
	}
	return false
}

func (cm *clientManager) propagate(msg []byte, messageID string) {
	if cm.clients == nil {
		return
	}
	for _, consumer := range *cm.clients {
		if consumer == nil {
			continue
		}
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
		keys := make(map[string]bool)
		for _, peer := range peerList {
			peerKnownPeers, err := peer.peerList()
			if err != nil {
				continue
			}

			for _, unknownPeer := range peerKnownPeers {
				if _, value := keys[unknownPeer.SignKey]; !value {
					keys[unknownPeer.SignKey] = true
					if unknownPeer.online() {
						peerInfo, err := unknownPeer.info()
						if err != nil {
							continue
						}
						checkPeer := Peer{}
						cm.core.db.db.Find(&checkPeer, "sign_key = ?", peerInfo.PubSignKey)
						if checkPeer == (Peer{}) {
							unknownPeer.Acessible = true
							unknownPeer.SignKey = peerInfo.PubSignKey
							unknownPeer.LastSeen = time.Now()
							cm.core.db.db.Create(&unknownPeer)
							log.Info("findPeers() Discovered peer: " + unknownPeer.toString(false) + " " + unknownPeer.SignKey)
						}
					}
				}
			}
		}
		time.Sleep(3 * time.Minute)
	}

}

func (cm *clientManager) takePeers() {
	for {
		if len(*cm.clients) < 8 {
			peer := Peer{}
			cm.core.db.db.Raw("SELECT * FROM peers WHERE acessible = ? ORDER BY RANDOM() LIMIT 1;", true).Scan(&peer)
			if !cm.inClientList(peer) && peer.online() {
				cm.core.db.db.Model(&Peer{}).Where("sign_key = ?", peer.SignKey).Updates(Peer{LastSeen: time.Now()})
				c := client{}
				go c.initialize(cm.core, &peer, &cm.clientReceived, &cm.readMu)
				cm.addToCoClientList(&c)
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func (cm *clientManager) pruneList() {
	for {
		cm.clientMu.Lock()
		for i, c := range *cm.clients {
			if c.failed || c.conn == nil {
				dbEntry := Peer{}
				cm.core.db.db.Where("sign_key = ?", c.peer.SignKey).Find(&dbEntry)

				if dbEntry.FailCount > 5 {
					cm.core.db.db.Delete(&dbEntry, "sign_key = ?", dbEntry.SignKey)
				} else {
					cm.core.db.db.Model(&Peer{}).Where("sign_key = ?", dbEntry.SignKey).Updates(Peer{FailCount: dbEntry.FailCount + 1})
				}

				(*cm.clients)[i] = (*cm.clients)[len((*cm.clients))-1] // Copy last element to index i.
				(*cm.clients)[len((*cm.clients))-1] = nil              // Erase last element (write zero value).
				(*cm.clients) = (*cm.clients)[:len((*cm.clients))-1]   // Truncate slice.
				break
			}
		}
		cm.clientMu.Unlock()
		time.Sleep(1 * time.Second)
	}

}

func (cm *clientManager) addToCoClientList(newClient *client) {
	cm.clientMu.Lock()
	defer cm.clientMu.Unlock()
	*cm.clients = append(*cm.clients, newClient)
}

func (cm *clientManager) inClientList(peer Peer) bool {
	cm.clientMu.Lock()
	defer cm.clientMu.Unlock()
	for _, c := range *cm.clients {
		if c.peer.SignKey == peer.SignKey {
			return true
		}
	}
	return false
}
