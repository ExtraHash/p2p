package p2p

import (
	"os"

	"github.com/op/go-logging"
)

var progName string = "ExtraP2P"
var version string = "v0.2.1"
var log *logging.Logger = logging.MustGetLogger(progName)
var homedir, _ = os.UserHomeDir()
