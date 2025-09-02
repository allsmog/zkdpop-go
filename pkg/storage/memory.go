package storage

import (
	"sync"
	"time"
)

// MemoryStore implements the Store interface using in-memory storage
// This is suitable for development and testing, but not for production
type MemoryStore struct {
	mu        sync.RWMutex
	users     map[string]*User
	sessions  map[string]*ZKSession
	denylist  map[string]bool
}

// NewMemoryStore creates a new in-memory store
func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		users:    make(map[string]*User),
		sessions: make(map[string]*ZKSession),
		denylist: make(map[string]bool),
	}

	// Start cleanup goroutine
	go store.cleanupLoop()

	return store
}

// cleanupLoop runs periodic cleanup of expired sessions
func (s *MemoryStore) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.CleanupExpiredSessions(2 * time.Minute)
	}
}

// CreateUser registers a new user
func (s *MemoryStore) CreateUser(pk string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[pk]; exists {
		return ErrUserExists
	}

	s.users[pk] = &User{
		PK:        pk,
		Status:    "active",
		CreatedAt: time.Now(),
	}

	return nil
}

// GetUser retrieves a user by public key
func (s *MemoryStore) GetUser(pk string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[pk]
	if !exists {
		return nil, ErrUserNotFound
	}

	// Return a copy to avoid race conditions
	userCopy := *user
	return &userCopy, nil
}

// UpdateUserStatus updates a user's status
func (s *MemoryStore) UpdateUserStatus(pk string, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[pk]
	if !exists {
		return ErrUserNotFound
	}

	user.Status = status
	return nil
}

// ListUsers returns all users
func (s *MemoryStore) ListUsers() ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, *user)
	}

	return users, nil
}

// CreateSession creates a new ZK session
func (s *MemoryStore) CreateSession(session *ZKSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Set creation time
	session.CreatedAt = time.Now()

	// Store a copy to avoid race conditions
	sessionCopy := *session
	s.sessions[session.ID] = &sessionCopy

	return nil
}

// GetSession retrieves a session by ID
func (s *MemoryStore) GetSession(sessionID string) (*ZKSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	// Check if session is expired (2 minutes)
	if time.Since(session.CreatedAt) > 2*time.Minute {
		return nil, ErrSessionExpired
	}

	// Return a copy to avoid race conditions
	sessionCopy := *session
	return &sessionCopy, nil
}

// MarkSessionUsed marks a session as used
func (s *MemoryStore) MarkSessionUsed(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}

	if session.Used {
		return ErrSessionUsed
	}

	session.Used = true
	return nil
}

// CleanupExpiredSessions removes expired sessions
func (s *MemoryStore) CleanupExpiredSessions(maxAge time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	
	for id, session := range s.sessions {
		if session.CreatedAt.Before(cutoff) {
			delete(s.sessions, id)
		}
	}

	return nil
}

// GetSessionsByPK returns all sessions for a public key
func (s *MemoryStore) GetSessionsByPK(pk string) ([]ZKSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sessions []ZKSession
	for _, session := range s.sessions {
		if session.PK == pk {
			sessions = append(sessions, *session)
		}
	}

	return sessions, nil
}

// AddToDenylist bans a public key
func (s *MemoryStore) AddToDenylist(pk string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.denylist[pk] = true
	return nil
}

// IsInDenylist checks if a public key is banned
func (s *MemoryStore) IsInDenylist(pk string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.denylist[pk], nil
}

// RemoveFromDenylist unbans a public key
func (s *MemoryStore) RemoveFromDenylist(pk string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.denylist, pk)
	return nil
}

// ListDenylist returns all banned public keys
func (s *MemoryStore) ListDenylist() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pks := make([]string, 0, len(s.denylist))
	for pk := range s.denylist {
		pks = append(pks, pk)
	}

	return pks, nil
}

// Close closes the store (no-op for memory store)
func (s *MemoryStore) Close() error {
	return nil
}

// Ping checks if the store is healthy (always true for memory store)
func (s *MemoryStore) Ping() error {
	return nil
}

// Stats returns storage statistics for monitoring
func (s *MemoryStore) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]int{
		"users":     len(s.users),
		"sessions":  len(s.sessions),
		"denylist":  len(s.denylist),
	}
}