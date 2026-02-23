package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/allsmog/zkdpop-go/pkg/crypto/curve"
	"github.com/allsmog/zkdpop-go/pkg/crypto/schnorr"
	"github.com/allsmog/zkdpop-go/pkg/dpop"
	"github.com/allsmog/zkdpop-go/pkg/jwt"
	"github.com/allsmog/zkdpop-go/pkg/storage"
)

// Handlers contains all authentication handlers
type Handlers struct {
	store       storage.Store
	curve       curve.Curve
	tokenSigner jwt.TokenSigner
	replayStore dpop.ReplayStore
	config      Config
}

// Config contains configuration for auth handlers
type Config struct {
	Issuer     string        // JWT issuer
	Audience   string        // JWT audience
	TokenTTL   time.Duration // JWT lifetime
	SessionTTL time.Duration // ZK session lifetime
}

// NewHandlers creates new authentication handlers
func NewHandlers(
	store storage.Store,
	curve curve.Curve,
	tokenSigner jwt.TokenSigner,
	replayStore dpop.ReplayStore,
	config Config,
) *Handlers {
	return &Handlers{
		store:       store,
		curve:       curve,
		tokenSigner: tokenSigner,
		replayStore: replayStore,
		config:      config,
	}
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	PK   string                 `json:"pk"`   // Public key (hex/compressed)
	Meta map[string]interface{} `json:"meta"` // Optional metadata
}

// StartCommitRequest represents the initial ZK login request
type StartCommitRequest struct {
	PK     string `json:"pk"`     // Public key (hex/compressed)
	T      string `json:"T"`      // Commitment point (hex/compressed)
	Aud    string `json:"aud"`    // Audience
	Path   string `json:"path"`   // Request path
	Method string `json:"method"` // HTTP method
}

// StartCommitResponse represents the challenge response
type StartCommitResponse struct {
	SessionID       string `json:"session_id"`       // Session identifier
	C               string `json:"c"`                // Challenge scalar (hex)
	Timeslice       string `json:"timeslice"`        // RFC3339 timestamp
	ServerEphemeral string `json:"server_ephemeral"` // Server randomness (hex)
}

// CompleteRequest represents the ZK login completion request
type CompleteRequest struct {
	SessionID string `json:"session_id"` // Session identifier
	S         string `json:"s"`          // Response scalar (hex)
}

// CompleteResponse represents the token response
type CompleteResponse struct {
	AccessToken string `json:"access_token"` // JWT token
	ExpiresIn   int64  `json:"expires_in"`   // Seconds until expiry
}

// Register handles user registration
func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate public key
	pkBytes, err := decodeHex(req.PK)
	if err != nil {
		http.Error(w, "invalid public key format", http.StatusBadRequest)
		return
	}

	// Parse and validate point
	point, err := h.curve.ParsePoint(pkBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid public key: %v", err), http.StatusBadRequest)
		return
	}

	if err := h.curve.ValidatePoint(point); err != nil {
		http.Error(w, fmt.Sprintf("invalid public key: %v", err), http.StatusBadRequest)
		return
	}

	// Check if user is banned
	banned, err := h.store.IsInDenylist(req.PK)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if banned {
		http.Error(w, "public key is banned", http.StatusForbidden)
		return
	}

	// Create user
	if err := h.store.CreateUser(req.PK); err != nil {
		if err == storage.ErrUserExists {
			http.Error(w, "user already exists", http.StatusConflict)
		} else {
			http.Error(w, "storage error", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "created"})
}

// StartCommit handles the ZK login commitment phase
func (h *Handlers) StartCommit(w http.ResponseWriter, r *http.Request) {
	// Verify DPoP proof
	dpopResult, err := dpop.VerifyDPoP(r, h.replayStore)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid DPoP proof: %v", err), http.StatusUnauthorized)
		return
	}

	var req StartCommitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate public key exists and is not banned
	user, err := h.store.GetUser(req.PK)
	if err != nil {
		if err == storage.ErrUserNotFound {
			http.Error(w, "user not found", http.StatusNotFound)
		} else {
			http.Error(w, "storage error", http.StatusInternalServerError)
		}
		return
	}

	if user.Status != "active" {
		http.Error(w, "user is not active", http.StatusForbidden)
		return
	}

	banned, err := h.store.IsInDenylist(req.PK)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if banned {
		http.Error(w, "public key is banned", http.StatusForbidden)
		return
	}

	// Parse and validate commitment point T
	TBytes, err := decodeHex(req.T)
	if err != nil {
		http.Error(w, "invalid commitment format", http.StatusBadRequest)
		return
	}

	TPoint, err := h.curve.ParsePoint(TBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid commitment: %v", err), http.StatusBadRequest)
		return
	}

	if err := h.curve.ValidatePoint(TPoint); err != nil {
		http.Error(w, fmt.Sprintf("invalid commitment: %v", err), http.StatusBadRequest)
		return
	}

	// Generate timeslice (minute granularity)
	timeslice := time.Now().UTC().Truncate(time.Minute)

	// Generate server ephemeral (32 random bytes)
	serverEphemeral := make([]byte, 32)
	if _, err := rand.Read(serverEphemeral); err != nil {
		http.Error(w, "failed to generate randomness", http.StatusInternalServerError)
		return
	}

	// Derive context and challenge
	ctx := schnorr.DeriveContext(req.Aud, req.Path, req.Method, timeslice.Format(time.RFC3339), serverEphemeral)
	
	pkBytes, err := decodeHex(req.PK)
	if err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}

	challenge, err := schnorr.DeriveChallenge(h.curve, TBytes, pkBytes, ctx)
	if err != nil {
		http.Error(w, "failed to derive challenge", http.StatusInternalServerError)
		return
	}

	// Create session
	sessionID := uuid.New().String()
	session := &storage.ZKSession{
		ID:              sessionID,
		PK:              req.PK,
		T:               TBytes,
		C:               challenge,
		Timeslice:       timeslice,
		ServerEphemeral: serverEphemeral,
		JKT:             dpopResult.JKT,
		Used:            false,
	}

	if err := h.store.CreateSession(session); err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	// Return challenge
	response := StartCommitResponse{
		SessionID:       sessionID,
		C:               encodeHex(challenge),
		Timeslice:       timeslice.Format(time.RFC3339),
		ServerEphemeral: encodeHex(serverEphemeral),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Complete handles the ZK login completion phase
func (h *Handlers) Complete(w http.ResponseWriter, r *http.Request) {
	// Verify DPoP proof
	dpopResult, err := dpop.VerifyDPoP(r, h.replayStore)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid DPoP proof: %v", err), http.StatusUnauthorized)
		return
	}

	var req CompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Get session
	session, err := h.store.GetSession(req.SessionID)
	if err != nil {
		if err == storage.ErrSessionNotFound {
			http.Error(w, "session not found", http.StatusNotFound)
		} else if err == storage.ErrSessionExpired {
			http.Error(w, "session expired", http.StatusGone)
		} else {
			http.Error(w, "storage error", http.StatusInternalServerError)
		}
		return
	}

	// Check session not already used
	if session.Used {
		http.Error(w, "session already used", http.StatusConflict)
		return
	}

	// Check DPoP key matches session
	if dpopResult.JKT != session.JKT {
		http.Error(w, "DPoP key mismatch", http.StatusUnauthorized)
		return
	}

	// Check timeslice freshness (≤ 2 minutes)
	if time.Since(session.Timeslice) > h.config.SessionTTL {
		http.Error(w, "session expired", http.StatusGone)
		return
	}

	// Parse response scalar
	sBytes, err := decodeHex(req.S)
	if err != nil {
		http.Error(w, "invalid response format", http.StatusBadRequest)
		return
	}

	// Verify Schnorr proof
	pkBytes, err := decodeHex(session.PK)
	if err != nil {
		http.Error(w, "invalid session public key", http.StatusInternalServerError)
		return
	}

	result, err := schnorr.VerifySchnorr(h.curve, pkBytes, session.T, session.C, sBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("verification error: %v", err), http.StatusInternalServerError)
		return
	}

	if !result.Valid {
		http.Error(w, "invalid Schnorr proof", http.StatusUnauthorized)
		return
	}

	// Mark session as used
	if err := h.store.MarkSessionUsed(req.SessionID); err != nil {
		http.Error(w, "failed to mark session used", http.StatusInternalServerError)
		return
	}

	// Generate subject identifier
	subject := jwt.GeneratePairwiseSubject(pkBytes, h.config.Audience)

	// Mint JWT with cnf.jkt binding
	token, err := jwt.MintZKDPoPToken(
		h.tokenSigner,
		h.config.Issuer,
		subject,
		h.config.Audience,
		session.JKT,
		session.T,
		session.C,
		session.Timeslice,
		h.curve.Name(),
		h.config.TokenTTL,
	)
	if err != nil {
		http.Error(w, "failed to mint token", http.StatusInternalServerError)
		return
	}

	// Return token
	response := CompleteResponse{
		AccessToken: token,
		ExpiresIn:   int64(h.config.TokenTTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// JWKS returns the public keys for JWT verification
func (h *Handlers) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.tokenSigner.JWKS()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // Cache for 5 minutes

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		http.Error(w, "failed to encode JWKS", http.StatusInternalServerError)
		return
	}
}

// decodeHex decodes a hexadecimal string
func decodeHex(s string) ([]byte, error) {
	// Remove 0x prefix if present
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	
	// Decode base64url if not hex
	if len(s)%2 != 0 || !isHex(s) {
		return base64.RawURLEncoding.DecodeString(s)
	}
	
	// Decode hex
	bytes := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b := hexToByte(s[i])<<4 + hexToByte(s[i+1])
		bytes[i/2] = b
	}
	
	return bytes, nil
}

// encodeHex encodes bytes as hexadecimal
func encodeHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, c := range b {
		s[i*2] = hexChars[c>>4]
		s[i*2+1] = hexChars[c&0x0f]
	}
	return string(s)
}

// isHex checks if string contains only hex characters
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// hexToByte converts hex character to byte
func hexToByte(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 10
	}
	if c >= 'A' && c <= 'F' {
		return c - 'A' + 10
	}
	return 0
}