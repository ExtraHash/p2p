package p2p

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"testing"
	"time"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/nacl/box"
)

var testConfig = NetworkConfig{
	Port:      10187,
	LogLevel:  0,
	NetworkID: "35c36251-96b7-4e2a-b0bb-de40223d3034",
	Seeds: []Peer{
		{Host: "lbserver1.ddns.net", Port: 10187, SignKey: "c2bc4d085b46c61bfabf7e0c2809d7aba7421ad9057148d9831c2463a2b61f80"},
	},
}

func TestSign(t *testing.T) {
	keys := keys{}
	err := keys.initialize(testConfig)
	if err != nil {
		t.Error(err)
	}

	msg := []byte("hunter2")
	sig := ed25519.Sign(keys.signKeys.Priv, msg)
	if !ed25519.Verify(keys.signKeys.Pub, msg, sig) {
		t.Error("ed25519 signature did not verify")
	}
}

func TestSeal(t *testing.T) {
	keys := keys{}
	err := keys.initialize(testConfig)
	if err != nil {
		t.Error(err)
	}

	recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	msg := []byte("Alas, poor Yorick! I knew him, Horatio")
	// This encrypts msg and appends the result to the nonce.
	encrypted := box.Seal(nonce[:], msg, &nonce, recipientPublicKey, &keys.sealKeys.Priv)

	// The recipient can decrypt the message using their private key and the
	// sender's public key. When you decrypt, you must use the same nonce you
	// used to encrypt the message. One way to achieve this is to store the
	// nonce alongside the encrypted message. Above, we stored the nonce in the
	// first 24 bytes of the encrypted text.
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	_, ok := box.Open(nil, encrypted[24:], &decryptNonce, &keys.sealKeys.Pub, recipientPrivateKey)
	if !ok {
		t.Error("Encryption/decryption failed.")
	}
}

func TestAPI(t *testing.T) {
	messages := make(chan []byte)
	core := core{}
	core.messages = &messages
	core.config = testConfig

	_, err := uuid.FromString(testConfig.NetworkID)
	if err != nil {
		t.Error("Error parsing network ID. Network ID must be a valid UUID string.")
	}

	err = core.keys.initialize(testConfig)
	if err != nil {
		t.Log("failed at keys initialize", err)
	}
	err = core.db.initialize(testConfig)
	if err != nil {
		t.Log("failed at db initialize", err)
	}

	api := api{}
	api.initialize(&core)
	go api.run()
	time.Sleep(2 * time.Second)
	_, err = http.Get("http://localhost:10187/info")
	if err != nil {
		t.Error("failed at web request:", err)
	}
}

func TestNetwork(t *testing.T) {
	config := NetworkConfig{
		Port:      10187,
		LogLevel:  1,
		NetworkID: "35c36251-96b7-4e2a-b0bb-de40223d3034",
		Seeds: []Peer{
			{Host: "lbserver1.ddns.net", Port: 10187, SignKey: "c2bc4d085b46c61bfabf7e0c2809d7aba7421ad9057148d9831c2463a2b61f80"},
		},
	}

	p2p := DP2P{}

	go (func() {
		err := p2p.Initialize(config)
		if err != nil {
			t.Error("P2P failed to initialize", err)
		}
	})()

	token := randomData()

	go (func() {
		for {
			time.Sleep(1 * time.Second)
			p2p.Broadcast(token)

			t.Log(p2p.GetPeerList())
		}
	})()

	received := 0
	for {
		message := p2p.ReadMessage()

		if bytes.Equal(message, token) {
			received++
			t.Log(string(message))
			if received > 100 {
				return
			}
		}
	}
}

func randomData() []byte {
	token := make([]byte, 32)
	rand.Read(token)
	// return token
	return []byte(hex.EncodeToString(token))
}
