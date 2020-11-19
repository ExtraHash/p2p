package p2p

import (
	"sync"
)

type peerList struct {
	list      []Peer
	mu        sync.Mutex
	maxLength int
}

func (l *peerList) setMaxLength(length int) {
	l.maxLength = length
}

func (l *peerList) push(value Peer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, value)

	if len(l.list) > l.maxLength {
		l.unshift()
	}
}

func (l *peerList) pop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = l.list[:len(l.list)-1]
}

func (l *peerList) shift(value Peer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append([]Peer{value}, l.list...)

	if len(l.list) > l.maxLength {
		l.pop()
	}
}

func (l *peerList) unshift() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = l.list[1:]
}

func (l *peerList) contains(e Peer) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range l.list {
		if a.SignKey == e.SignKey {
			return true
		}
	}
	return false
}

func (l *peerList) remove(e Peer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, a := range l.list {
		if a.SignKey == e.SignKey {
			l.list = append(l.list[:i], l.list[i+1:]...)
		}
	}
}
