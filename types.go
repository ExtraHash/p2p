package p2p

import (
	"crypto/ed25519"
	"time"

	"gorm.io/gorm"
)

type xNonce struct {
	bytes *[24]byte
	str   string
}

type message struct {
	Type string `msgpack:"type"`
}

type challenge struct {
	Type      string `msgpack:"type"`
	Challenge string `msgpack:"challenge"`
}

type response struct {
	Type      string `msgpack:"type"`
	Signed    string `msgpack:"signed"`
	SignKey   string `msgpack:"signKey"`
	SealKey   string `msgpack:"sealKey"`
	Port      int    `msgpack:"port"`
	NetworkID string `msgpack:"networkID"`
}

type broadcast struct {
	Type      string `msgpack:"type"`
	Secret    string `msgpack:"secret"`
	Nonce     string `msgpack:"nonce"`
	MessageID string `msgpack:"messageID"`
}

type infoRes struct {
	PubSignKey string `json:"pubSignKey"`
	PubSealKey string `json:"pubSealKey"`
	Version    string `json:"version"`
}

type verifyRes struct {
	Message string `json:"message"`
	Signed  string `json:"signed"`
}

type apiModel struct {
	ID        uint           `gorm:"primarykey" json:"-"`
	CreatedAt time.Time      `json:"-"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// SignKeys is a type that contains a Public and private ed25519 key.
type SignKeys struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

// SealKeys contains a pair of x25519 encryption keys.
type SealKeys struct {
	Pub  [32]byte
	Priv [32]byte
}
