package p2p

import (
	"encoding/hex"
	"sync"

	uuid "github.com/satori/go.uuid"
)

// DP2P is the main struct for the p2p operations
type DP2P struct {
	db                db
	api               api
	keys              keys
	activeConnections []*ActiveConnection
	consumerList      clientList
	selfClient        client
	clientReceived    lockList
	serverReceived    lockList
	clRecvLock        sync.Mutex
	selfPeer          Peer
	config            NetworkConfig
	readMu            sync.Mutex
	messages          *chan []byte
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
	d.messages = &messages

	d.config = config

	_, err := uuid.FromString(config.NetworkID)
	if err != nil {
		log.Error("Error parsing network ID. Network ID must be a valid UUID string.")
		log.Fatal(err)
	}

	d.clientReceived.setMaxLength(1000)
	d.serverReceived.setMaxLength(1000)
	d.activeConnections = []*ActiveConnection{}

	LoggerConfig()
	d.keys.initialize(config)
	d.db.initialize(config)

	d.selfPeer = Peer{
		Host:    "127.0.0.1",
		Port:    d.config.Port,
		SignKey: hex.EncodeToString(d.keys.signKeys.Pub),
		SealKey: hex.EncodeToString(d.keys.sealKeys.Pub[:]),
	}

	d.api.initialize(d.config, d.keys, d.db, &d.activeConnections, &d.consumerList, &d.clientReceived, &d.readMu, d.messages)

	go d.postAPISetup()
	d.api.run()
}

// Broadcast a message on the network. Returns the created message's ID.
func (d *DP2P) Broadcast(message []byte) uuid.UUID {
	mID := uuid.NewV4()
	d.selfClient.propagate(message, mID.String())
	return mID
}

// ReadMessage will get the next broadcasted message on the network. It blocks
// until the message is ready to be read.
func (d *DP2P) ReadMessage() []byte {
	return <-*d.messages
}

func (d *DP2P) postAPISetup() {
	go d.selfClient.initialize(d.config, d.selfPeer, d.keys, &d.api, &d.consumerList, &d.clientReceived, d.db, &d.readMu, d.messages)
	go d.consumerList.initialize(d.config, 1000, d.db, &d.api, d.keys, &d.clientReceived, &d.readMu, d.messages)
}
