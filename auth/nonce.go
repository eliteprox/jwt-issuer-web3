package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const (
	// NonceBytes is the number of random bytes used to generate a nonce.
	NonceBytes = 16
	// NonceTTL is how long a nonce remains valid before expiring.
	NonceTTL = 5 * time.Minute
	// NonceMaxPending is the maximum number of pending nonces to prevent DoS.
	NonceMaxPending = 10000
	// nonceCleanupInterval is how often the background cleaner runs.
	nonceCleanupInterval = 1 * time.Minute
)

// nonceEntry tracks a pending nonce with its creation time.
type nonceEntry struct {
	createdAt time.Time
}

// NonceStore is a thread-safe store for pending SIWE nonces.
type NonceStore struct {
	mu      sync.Mutex
	nonces  map[string]nonceEntry
	closeCh chan struct{}
}

// NewNonceStore creates a new nonce store and starts a background cleanup goroutine.
func NewNonceStore() *NonceStore {
	ns := &NonceStore{
		nonces:  make(map[string]nonceEntry),
		closeCh: make(chan struct{}),
	}
	go ns.cleanupLoop()
	return ns
}

// Generate creates a new random nonce, stores it, and returns it.
func (ns *NonceStore) Generate() (string, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if len(ns.nonces) >= NonceMaxPending {
		return "", fmt.Errorf("too many pending nonces")
	}

	b := make([]byte, NonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(b)
	ns.nonces[nonce] = nonceEntry{createdAt: time.Now()}
	return nonce, nil
}

// Consume validates and removes a nonce. Returns true if the nonce was valid.
func (ns *NonceStore) Consume(nonce string) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	entry, exists := ns.nonces[nonce]
	if !exists {
		return false
	}
	delete(ns.nonces, nonce)

	if time.Since(entry.createdAt) > NonceTTL {
		return false
	}
	return true
}

// cleanupLoop periodically removes expired nonces.
func (ns *NonceStore) cleanupLoop() {
	ticker := time.NewTicker(nonceCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ns.mu.Lock()
			now := time.Now()
			for nonce, entry := range ns.nonces {
				if now.Sub(entry.createdAt) > NonceTTL {
					delete(ns.nonces, nonce)
				}
			}
			ns.mu.Unlock()
		case <-ns.closeCh:
			return
		}
	}
}

// Close stops the background cleanup goroutine.
func (ns *NonceStore) Close() {
	close(ns.closeCh)
}

// Len returns the current number of pending nonces (for testing).
func (ns *NonceStore) Len() int {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return len(ns.nonces)
}
