package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"

	"golang.org/x/crypto/nacl/box"
)

type keys struct {
	keyFolder  string
	progFolder string
	signKeys   SignKeys
	sealKeys   SealKeys
	config     NetworkConfig
}

func (k *keys) initialize(config NetworkConfig) {
	k.config = config
	k.getProgFolder()
	k.ensureFilesExist()
	k.loadKeys()
	k.generateSealKeys()
}

func (k *keys) getProgFolder() {
	// obtain the program folder
	homedir, err := os.UserHomeDir()
	check(err)

	k.progFolder = homedir + "/." + progName
	k.keyFolder = homedir + "/." + progName + "/" + k.config.NetworkID
}

func (k *keys) ensureFilesExist() {
	if !fileExists(k.progFolder) {
		log.Info(colors.boldWhite+"KEYS"+colors.reset, "Creating program folder.")
		os.Mkdir(k.progFolder, 0700)
	}

	if !fileExists(k.keyFolder) {
		log.Info(colors.boldWhite+"KEYS"+colors.reset, "Creating key folder.")
		os.Mkdir(k.keyFolder, 0700)
	}

	if !fileExists(k.keyFolder + "/signKey.priv") {
		k.writeSignKeys()
	}

}

func (k *keys) writeSignKeys() {
	log.Info(colors.boldWhite+"KEYS"+colors.reset, "Creating keyfiles.")
	if !fileExists(k.keyFolder + "/signKey.pub") {
		os.Create(k.keyFolder + "/signKey.pub")
	}
	if !fileExists(k.keyFolder + "/signKey.priv") {
		os.Create(k.keyFolder + "/signKey.priv")
	}

	k.signKeys = k.generateSignKeys()

	writeBytesToFile(k.keyFolder+"/signKey.pub", k.signKeys.Pub)
	writeBytesToFile(k.keyFolder+"/signKey.priv", k.signKeys.Priv)
}

func (k *keys) loadKeys() {
	k.signKeys.Pub = readBytesFromFile(k.keyFolder + "/signKey.pub")
	k.signKeys.Priv = readBytesFromFile(k.keyFolder + "/signKey.priv")

	log.Info(colors.boldWhite+"KEYS"+colors.reset, "Public signing key: "+hex.EncodeToString(k.signKeys.Pub))
}

func (k *keys) generateSignKeys() SignKeys {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err)

	signKeys := SignKeys{}
	signKeys.Pub = pub
	signKeys.Priv = priv

	return signKeys
}

func (k *keys) generateSealKeys() {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	check(err)

	slicePub := pubKey[:]

	k.sealKeys.Pub = *pubKey
	k.sealKeys.Priv = *privKey

	log.Info(colors.boldWhite+"KEYS"+colors.reset, "Public sealing key: "+hex.EncodeToString(slicePub))
}
