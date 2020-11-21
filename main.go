package p2p

import (
	"time"

	uuid "github.com/satori/go.uuid"
)

// DP2P is the main struct for the p2p operations
type DP2P struct {
	core core

	// don't get passed anywhere
	api           api
	clientManager clientManager
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
func (d *DP2P) Initialize(config NetworkConfig) {
	messages := make(chan []byte)
	d.core.messages = &messages

	d.core.config = config

	_, err := uuid.FromString(config.NetworkID)
	if err != nil {
		log.Error("Error parsing network ID. Network ID must be a valid UUID string.")
		log.Fatal(err)
	}

	LoggerConfig(config)
	d.core.keys.initialize(config)
	d.core.db.initialize(config)

	d.api.initialize(&d.core)

	d.clientManager.initialize(&d.core)

	go d.postAPISetup()
	d.api.run()
}

// Broadcast a message on the network. Returns the created message's ID.
func (d *DP2P) Broadcast(message []byte) uuid.UUID {
	mID := uuid.NewV4()
	d.clientManager.propagate(message, mID.String())
	return mID
}

// ReadMessage will get the next broadcasted message on the network. It blocks
// until the message is ready to be read.
func (d *DP2P) ReadMessage() []byte {
	for d.core.messages == nil {
		time.Sleep(100 * time.Millisecond)
	}
	return <-*d.core.messages
}

func (d *DP2P) postAPISetup() {

}
