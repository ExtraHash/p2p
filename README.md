# extrahash/p2p

A p2p network library in go.

Usage:

```go
package main

import (
	"crypto/rand"
	"flag"
	"time"

	"github.com/ExtraHash/p2p"
)

func main() {
    // seed nodes for your network. You must have at least one and it must be open to the network.
	seeds := []p2p.Peer{
		{Host: "127.0.0.1", Port: 10187, SignKey: "c2bc4d085b46c61bfabf7e0c2809d7aba7421ad9057148d9831c2463a2b61f80"},
	}

	config := p2p.NetworkConfig{
		Port:      10187,
        LogLevel:  1,
        // this needs to be a unique uuid string. every peer in your network should identify with it.
		NetworkID: "35c36251-96b7-4e2a-b0bb-de40223d3034",
		Seeds:     seeds,
	}

	p2p := p2p.DP2P{}
	go p2p.Initialize(config)

	for {
        time.Sleep(5 * time.Second)
        // broadcast any arbitrary []byte to the network.
		p2p.Broadcast(randomData())
	}
}

func randomData() []byte {
	token := make([]byte, 32)
	rand.Read(token)
	return token
}
```