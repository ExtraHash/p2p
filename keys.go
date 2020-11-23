package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
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

func (k *keys) initialize(config NetworkConfig) error {
	k.config = config
	err := k.getProgFolder()
	if err != nil {
		return err
	}
	err = k.ensureFilesExist()
	if err != nil {
		return err
	}
	err = k.loadKeys()
	if err != nil {
		return err
	}
	err = k.generateSealKeys()
	if err != nil {
		return err
	}
	return nil
}

func (k *keys) getProgFolder() error {
	// obtain the program folder
	homedir, err := os.UserHomeDir()

	if err != nil {
		return err
	}

	k.progFolder = homedir + "/." + progName
	k.keyFolder = homedir + "/." + progName + "/" + k.config.NetworkID

	return nil
}

func (k *keys) ensureFilesExist() error {
	if !fileExists(k.progFolder) {
		err := os.Mkdir(k.progFolder, 0700)
		if err != nil {
			return err
		}
	}

	if !fileExists(k.keyFolder) {
		err := os.Mkdir(k.keyFolder, 0700)
		if err != nil {
			return err
		}
	}

	if !fileExists(k.keyFolder + "/signKey.priv") {
		err := k.writeSignKeys()
		if err != nil {
			return err
		}
	}

	return nil
}

func (k *keys) writeSignKeys() error {
	if !fileExists(k.keyFolder + "/signKey.pub") {
		_, err := os.Create(k.keyFolder + "/signKey.pub")
		if err != nil {
			return err
		}
	}
	if !fileExists(k.keyFolder + "/signKey.priv") {
		_, err := os.Create(k.keyFolder + "/signKey.priv")
		if err != nil {
			return err
		}
	}

	k.signKeys = k.generateSignKeys()

	err := writeBytesToFile(k.keyFolder+"/signKey.pub", k.signKeys.Pub)
	if err != nil {
		return err
	}
	err = writeBytesToFile(k.keyFolder+"/signKey.priv", k.signKeys.Priv)
	if err != nil {
		return err
	}

	return nil
}

func (k *keys) loadKeys() error {
	pubKey, err := readBytesFromFile(k.keyFolder + "/signKey.pub")
	if err != nil {
		return err
	}
	k.signKeys.Pub = pubKey

	privKey, err := readBytesFromFile(k.keyFolder + "/signKey.priv")
	if err != nil {
		return err
	}
	k.signKeys.Priv = privKey
	return nil
}

func (k *keys) generateSignKeys() SignKeys {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err)

	signKeys := SignKeys{}
	signKeys.Pub = pub
	signKeys.Priv = priv

	return signKeys
}

func (k *keys) generateSealKeys() error {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	k.sealKeys.Pub = *pubKey
	k.sealKeys.Priv = *privKey
	return nil
}
