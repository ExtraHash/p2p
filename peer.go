package p2p

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	uuid "github.com/satori/go.uuid"
)

// Peer is a single peer on the network
type Peer struct {
	apiModel
	Host       string `json:"host"`
	Port       int    `json:"port"`
	SignKey    string `json:"signKey" gorm:"unique"`
	SealKey    string `json:"-" gorm:"-"`
	Connected  bool   `json:"-" gorm:"-"`
	Connecting bool   `json:"-" gorm:"-"`
	FailCount  int    `json:"-" gorm:"-"`
}

func (p *Peer) verify(vID uuid.UUID) verifyRes {
	log.Notice("OUT", "GET", "/verify/"+vID.String(), p.toString(false))
	vRes, err := http.Get(p.toString(true) + "/verify/" + vID.String())
	if err != nil {
		log.Error(err)
		panic(err)
	}
	verBody, err := ioutil.ReadAll(vRes.Body)
	verify := verifyRes{}
	json.Unmarshal(verBody, &verify)

	return verify
}

func (p *Peer) info() infoRes {
	log.Notice("OUT", "GET", "/info", p.toString(false))
	iRes, err := http.Get(p.toString(true) + "/info")
	if err != nil {
		log.Error(err)
		panic(err)
	}

	infoBody, err := ioutil.ReadAll(iRes.Body)
	info := infoRes{}
	json.Unmarshal(infoBody, &info)

	return info
}

func (p *Peer) peerList() []Peer {
	log.Notice("OUT", "GET", "/peers", p.toString(false))
	iRes, err := http.Get(p.toString(true) + "/peers")
	if err != nil {
		log.Error(err)
		panic(err)
	}

	peerBody, err := ioutil.ReadAll(iRes.Body)
	peers := []Peer{}
	json.Unmarshal(peerBody, &peers)

	return peers
}

func (p *Peer) toString(includePrefix bool) string {
	if includePrefix {
		return "http://" + p.Host + ":" + strconv.Itoa(p.Port)
	}
	return p.Host + ":" + strconv.Itoa(p.Port)
}
