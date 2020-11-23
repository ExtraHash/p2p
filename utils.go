package p2p

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/op/go-logging"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func doEvery(d time.Duration, f func()) {
	for range time.Tick(d) {
		f()
	}
}

func splitIP(ip string) (string, int) {
	s := strings.Split(ip, ":")
	if len(s) != 2 {
		panic("bad ip string " + ip)
	}
	port, err := strconv.Atoi(s[1])
	if err != nil {
		panic("bad ip string " + ip)
	}
	return s[0], port
}

// GetIP from http request
func GetIP(r *http.Request) string {
	forwarded := r.Header.Get("X-FORWARDED-FOR")
	if forwarded != "" {
		return forwarded
	}

	return r.RemoteAddr
}

// LoggerConfig sets up the logger configuration.
func LoggerConfig(config NetworkConfig) {
	//initialize logger
	format := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} › %{color:reset}%{message}`,
	)
	backend := logging.NewLogBackend(os.Stdin, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	logging.SetBackend(backendFormatter)
}

func pass() {}

func sealToString(value [32]byte) []byte {
	return value[:]
}

func nonceSliceConvert(nonce []byte) *[24]byte {
	var fNonce [24]byte
	copy(fNonce[:], nonce[:24])
	return &fNonce
}
func contains(s [][]byte, e []byte) bool {
	for _, a := range s {
		if bytes.Equal(a, e) {
			return true
		}
	}
	return false
}

func makeNonce() xNonce {
	xn := xNonce{}

	token := make([]byte, 24)
	rand.Read(token)
	var nonce [24]byte
	copy(nonce[:], token[:24])

	xn.bytes = &nonce
	xn.str = hex.EncodeToString(token)

	return xn
}

func keySliceConvert(slice []byte) *[32]byte {
	var key [32]byte
	copy(key[:], slice[:32])
	return &key
}

func fileExists(filename string) bool {
	_, configErr := os.Stat(filename)
	if os.IsNotExist(configErr) {
		return false
	}
	return true
}

func writeBytesToFile(filename string, bytes []byte) error {
	file, err := os.OpenFile(filename, os.O_RDWR, 0700)
	if err != nil {
		return err
	}

	file.Write([]byte(hex.EncodeToString(bytes)))

	err = file.Sync()
	if err != nil {
		return err
	}

	file.Close()
	return nil
}

func readBytesFromFile(filename string) ([]byte, error) {
	// Open file for reading
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	bytes, _ := hex.DecodeString(string(data))
	return bytes, nil
}
