package p2p

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Peer is a single peer on the network
type Peer struct {
	apiModel
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	SignKey    string    `json:"signKey" gorm:"unique"`
	LastSeen   time.Time `json:"lastSeen"`
	SealKey    string    `json:"-" gorm:"-"`
	Connected  bool      `json:"-" gorm:"-"`
	Connecting bool      `json:"-" gorm:"-"`
	FailCount  int       `json:"-" gorm:"-"`
	Acessible  bool      `json:"-"`
	Direction  string    `json:"-" gorm:"-"`
}

func (p *Peer) info() (infoRes, error) {
	log.Notice(colors.boldYellow+"HTTP"+colors.reset, "OUT", "GET", "/info", p.toString(false))

	httpClient := http.Client{
		Timeout: 1 * time.Second,
	}

	iRes, err := httpClient.Get(p.toString(true) + "/info")
	if err != nil {
		log.Error(err)
		return infoRes{}, err
	}

	infoBody, err := ioutil.ReadAll(iRes.Body)
	if err != nil {
		log.Error(err)
		return infoRes{}, err
	}
	info := infoRes{}
	json.Unmarshal(infoBody, &info)

	return info, nil
}

func (p *Peer) peerList() ([]Peer, error) {
	log.Notice(colors.boldYellow+"HTTP"+colors.reset, "OUT", "GET", "/peers", p.toString(false))

	httpClient := http.Client{
		Timeout: 1 * time.Second,
	}

	iRes, err := httpClient.Get(p.toString(true) + "/peers")
	if err != nil {
		log.Error(err)
		return nil, err
	}

	peerBody, err := ioutil.ReadAll(iRes.Body)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	peers := []Peer{}
	json.Unmarshal(peerBody, &peers)

	return peers, err
}

func (p *Peer) toString(includePrefix bool) string {
	if includePrefix {
		return "http://" + p.Host + ":" + strconv.Itoa(p.Port)
	}
	return p.Host + ":" + strconv.Itoa(p.Port)
}

func (p *Peer) online() bool {
	log.Notice(colors.boldYellow+"HTTP"+colors.reset, "OUT", "GET", "/info", p.toString(false))
	infoURL := url.URL{Scheme: "http", Host: p.toString(false), Path: "/info"}
	httpClient := http.Client{
		Timeout: 1 * time.Second,
	}
	_, err := httpClient.Get(infoURL.String())
	if err != nil {
		return false
	}
	return true
}
