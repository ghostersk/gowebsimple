package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// PendingMFAStore holds temporary login tokens for users who have passed
// password check but still need to complete the TOTP challenge.
// Entries expire after 5 minutes.
type PendingMFAStore struct {
	mu      sync.Mutex
	entries map[string]*pendingEntry
}

type pendingEntry struct {
	UserID    int64
	Next      string
	ExpiresAt time.Time
}

func NewPendingMFAStore() *PendingMFAStore {
	s := &PendingMFAStore{entries: make(map[string]*pendingEntry)}
	go s.cleanup()
	return s
}

func (s *PendingMFAStore) Add(userID int64, next string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	s.mu.Lock()
	s.entries[token] = &pendingEntry{
		UserID:    userID,
		Next:      next,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	s.mu.Unlock()
	return token
}

func (s *PendingMFAStore) Has(token string) bool {
	return s.Get(token) != nil
}

func (s *PendingMFAStore) Get(token string) *pendingEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[token]
	if !ok || time.Now().After(e.ExpiresAt) {
		delete(s.entries, token)
		return nil
	}
	return e
}

func (s *PendingMFAStore) Delete(token string) {
	s.mu.Lock()
	delete(s.entries, token)
	s.mu.Unlock()
}

func (s *PendingMFAStore) cleanup() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for k, e := range s.entries {
			if now.After(e.ExpiresAt) {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
	}
}
