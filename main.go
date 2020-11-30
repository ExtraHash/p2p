package p2p

import (
	"time"

	uuid "github.com/satori/go.uuid"
)

// DP2P is the main struct for the p2p operations
type DP2P struct {
	core core

	// don't get passed anywhere
	api api
}

type core struct {
	config        NetworkConfig
	db            db
	keys          keys
	messages      *chan []byte
	clientManager clientManager
}

// NetworkConfig is the configuration for the p2p network.
type NetworkConfig struct {
	Port      int
	NetworkID string
	LogLevel  int
	Seeds     []Peer
}

// Initialize the peer to peer network connection.
func (d *DP2P) Initialize(config NetworkConfig) error {
	messages := make(chan []byte)
	d.core.messages = &messages
	d.core.config = config

	_, err := uuid.FromString(config.NetworkID)
	if err != nil {
		log.Error("Error parsing network ID. Network ID must be a valid UUID string.")
		return err
	}

	LoggerConfig(config)
	err = d.core.keys.initialize(config)
	if err != nil {
		return err
	}
	err = d.core.db.initialize(config)
	if err != nil {
		return err
	}
	d.api.initialize(&d.core)

	go d.postAPISetup()
	d.api.run()

	return nil
}

// Whisper a message to a single peer with the provided public sign key. Returns true if succesful.
func (d *DP2P) Whisper(message []byte, pubKey string) bool {
	mID := uuid.NewV4()
	if !d.core.clientManager.whisper(message, pubKey, mID.String()) {
		return d.api.whisper(message, pubKey, mID.String())
	}
	return true
}

// Broadcast a message on the network. Returns the created message's ID.
func (d *DP2P) Broadcast(message []byte) string {
	mID := uuid.NewV4()
	d.core.clientManager.propagate(message, mID.String())
	return mID.String()
}

// ReadMessage will get the next broadcasted message on the network. It blocks
// until the message is ready to be read.
func (d *DP2P) ReadMessage() []byte {
	for d.core.messages == nil {
		time.Sleep(100 * time.Millisecond)
	}
	return <-*d.core.messages
}

// GetPeerList returns all peers you are currently connected to.
func (d *DP2P) GetPeerList() []Peer {
	outPeers := d.core.clientManager.getPeerList()
	inPeers := d.api.getPeerList()

	allPeers := deDupe(append(outPeers, inPeers...))

	return allPeers
}

func deDupe(peers []Peer) []Peer {
	keys := make(map[Peer]bool)
	peerList := []Peer{}
	for _, peer := range peers {
		if _, value := keys[peer]; !value {
			keys[peer] = true
			peerList = append(peerList, peer)
		}
	}
	return peerList
}

func (d *DP2P) postAPISetup() {
	time.Sleep(2 * time.Second)
	d.core.clientManager.initialize(&d.core)
}
