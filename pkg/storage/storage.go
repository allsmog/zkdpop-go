package storage

import (
	"fmt"
	"time"
)

// User represents a registered user
type User struct {
	PK        string    `json:"pk" db:"pk"`               // Public key (hex/compressed point)
	Status    string    `json:"status" db:"status"`       // active|banned
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ZKSession represents a ZK authentication session
type ZKSession struct {
	ID              string    `json:"id" db:"id"`                             // Session ID (ULID/UUID)
	PK              string    `json:"pk" db:"pk"`                             // User's public key
	T               []byte    `json:"T" db:"t"`                               // Commitment point
	C               []byte    `json:"c" db:"c"`                               // Challenge scalar
	Timeslice       time.Time `json:"timeslice" db:"timeslice"`               // Minute-granularity timestamp
	ServerEphemeral []byte    `json:"server_ephemeral" db:"server_ephemeral"` // Server randomness
	JKT             string    `json:"jkt" db:"jkt"`                           // DPoP JWK thumbprint
	Used            bool      `json:"used" db:"used"`                         // Whether session has been used
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

// UserStore defines the interface for user storage
type UserStore interface {
	// CreateUser registers a new user
	CreateUser(pk string) error
	
	// GetUser retrieves a user by public key
	GetUser(pk string) (*User, error)
	
	// UpdateUserStatus updates a user's status
	UpdateUserStatus(pk string, status string) error
	
	// ListUsers returns all users (for admin purposes)
	ListUsers() ([]User, error)
}

// SessionStore defines the interface for ZK session storage
type SessionStore interface {
	// CreateSession creates a new ZK session
	CreateSession(session *ZKSession) error
	
	// GetSession retrieves a session by ID
	GetSession(sessionID string) (*ZKSession, error)
	
	// MarkSessionUsed marks a session as used
	MarkSessionUsed(sessionID string) error
	
	// CleanupExpiredSessions removes expired sessions
	CleanupExpiredSessions(maxAge time.Duration) error
	
	// GetSessionsByPK returns all sessions for a public key (debugging)
	GetSessionsByPK(pk string) ([]ZKSession, error)
}

// DenylistStore defines the interface for banned public keys
type DenylistStore interface {
	// AddToDenylist bans a public key
	AddToDenylist(pk string) error
	
	// IsInDenylist checks if a public key is banned
	IsInDenylist(pk string) (bool, error)
	
	// RemoveFromDenylist unbans a public key
	RemoveFromDenylist(pk string) error
	
	// ListDenylist returns all banned public keys
	ListDenylist() ([]string, error)
}

// Store combines all storage interfaces
type Store interface {
	UserStore
	SessionStore
	DenylistStore
	
	// Close closes the storage connection
	Close() error
	
	// Ping checks if the storage is healthy
	Ping() error
}

var (
	// ErrUserNotFound indicates a user was not found
	ErrUserNotFound = fmt.Errorf("user not found")
	
	// ErrUserExists indicates a user already exists
	ErrUserExists = fmt.Errorf("user already exists")
	
	// ErrSessionNotFound indicates a session was not found
	ErrSessionNotFound = fmt.Errorf("session not found")
	
	// ErrSessionExpired indicates a session has expired
	ErrSessionExpired = fmt.Errorf("session expired")
	
	// ErrSessionUsed indicates a session has already been used
	ErrSessionUsed = fmt.Errorf("session already used")
)