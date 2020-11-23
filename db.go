package p2p

import (
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type db struct {
	db     *gorm.DB
	config NetworkConfig
}

func (d *db) initialize(config NetworkConfig) error {
	d.config = config
	// initialize database, support sqlite and mysql
	homedir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	db, err := gorm.Open(sqlite.Open(homedir+"/."+progName+"/"+d.config.NetworkID+"/p2p.sqlite"), &gorm.Config{})
	if err != nil {
		return err
	}

	db.AutoMigrate(&Peer{})

	for _, seed := range config.Seeds {
		dbEntry := Peer{}
		db.Where("sign_key = ?", seed.SignKey).Find(&dbEntry)

		if dbEntry == (Peer{}) {
			db.Create(&seed)
		}
	}

	d.db = db
	log.Info(colors.boldWhite+"DATA"+colors.reset, "Database ready.")
	return nil
}

func (d *db) getPeerList() []Peer {
	peers := []Peer{}
	d.db.Find(&peers)
	return peers
}

func (d *db) addPeer(p Peer) {
	d.db.Create(&p)
}

func (d *db) getPeer(ip string) Peer {
	peer := Peer{}
	d.db.Where("host = ?", ip).Find(&peer)
	return peer
}
