package dpop

import (
	"fmt"
	"sync"
	"time"
)

// InMemoryReplayStore implements ReplayStore using an in-memory map
// This is suitable for single-instance deployments or development
type InMemoryReplayStore struct {
	mu      sync.RWMutex
	entries map[string]int64 // key -> expiry timestamp
	ttl     time.Duration    // how long to keep entries
}

// NewInMemoryReplayStore creates a new in-memory replay store
func NewInMemoryReplayStore(ttl time.Duration) *InMemoryReplayStore {
	store := &InMemoryReplayStore{
		entries: make(map[string]int64),
		ttl:     ttl,
	}

	// Start cleanup goroutine
	go store.cleanupLoop()

	return store
}

// Seen checks if a DPoP proof has been seen before and marks it as seen
func (s *InMemoryReplayStore) Seen(jkt, jti, htm, htu string, minute int64) bool {
	// Create key from all components
	key := fmt.Sprintf("%s:%s:%s:%s:%d", jkt, jti, htm, htu, minute)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already seen
	if _, exists := s.entries[key]; exists {
		return true // Replay detected
	}

	// Mark as seen with expiry
	s.entries[key] = time.Now().Add(s.ttl).Unix()
	return false
}

// Cleanup removes expired entries from the store
func (s *InMemoryReplayStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	for key, expiry := range s.entries {
		if expiry <= now {
			delete(s.entries, key)
		}
	}
}

// cleanupLoop runs periodic cleanup
func (s *InMemoryReplayStore) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.Cleanup()
	}
}

// Size returns the current number of entries (for testing/monitoring)
func (s *InMemoryReplayStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// NoOpReplayStore is a replay store that doesn't actually store anything
// This is useful for testing or when replay protection is not needed
type NoOpReplayStore struct{}

// NewNoOpReplayStore creates a new no-op replay store
func NewNoOpReplayStore() *NoOpReplayStore {
	return &NoOpReplayStore{}
}

// Seen always returns false (no replay detection)
func (s *NoOpReplayStore) Seen(jkt, jti, htm, htu string, minute int64) bool {
	return false
}

// Cleanup does nothing
func (s *NoOpReplayStore) Cleanup() {
	// No-op
}

// RedisReplayStore implements ReplayStore using Redis
// This is suitable for multi-instance deployments
type RedisReplayStore struct {
	client RedisClient
	ttl    time.Duration
}

// RedisClient defines the interface for Redis operations
type RedisClient interface {
	SetNX(key string, value interface{}, expiration time.Duration) (bool, error)
	Ping() error
}

// NewRedisReplayStore creates a new Redis-backed replay store
func NewRedisReplayStore(client RedisClient, ttl time.Duration) *RedisReplayStore {
	return &RedisReplayStore{
		client: client,
		ttl:    ttl,
	}
}

// Seen checks if a DPoP proof has been seen before and marks it as seen
func (s *RedisReplayStore) Seen(jkt, jti, htm, htu string, minute int64) bool {
	// Create key from all components
	key := fmt.Sprintf("dpop:%s:%s:%s:%s:%d", jkt, jti, htm, htu, minute)

	// Try to set the key (returns false if already exists)
	wasSet, err := s.client.SetNX(key, "1", s.ttl)
	if err != nil {
		// On error, assume not seen (fail open for availability)
		return false
	}

	// If we couldn't set it, it was already seen
	return !wasSet
}

// Cleanup is not needed for Redis as it handles TTL automatically
func (s *RedisReplayStore) Cleanup() {
	// Redis handles cleanup automatically via TTL
}