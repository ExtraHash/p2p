package p2p

import (
	"bytes"
	"sync"
)

type lockList struct {
	list      [][]byte
	mu        sync.Mutex
	maxLength int
}

func (l *lockList) setMaxLength(length int) {
	l.maxLength = length
}

func (l *lockList) push(value []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, value)

	if l.maxLength > 0 && len(l.list) > l.maxLength {
		l.unshift()
	}
}

func (l *lockList) pop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = l.list[:len(l.list)-1]
}

func (l *lockList) shift(value []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append([][]byte{value}, l.list...)

	if l.maxLength > 0 && len(l.list) > l.maxLength {
		l.pop()
	}
}

func (l *lockList) unshift() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = l.list[1:]
}

func (l *lockList) contains(e []byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range l.list {
		if bytes.Equal(a, e) {
			return true
		}
	}
	return false
}

func (l *lockList) remove(e []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, a := range l.list {
		if bytes.Equal(a, e) {
			l.list = append(l.list[:i], l.list[i+1:]...)
		}
	}
}
