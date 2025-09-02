package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/zkdpop/zkdpop-go/pkg/crypto/curve"
	"github.com/zkdpop/zkdpop-go/pkg/dpop"
	jwtpkg "github.com/zkdpop/zkdpop-go/pkg/jwt"
	"github.com/zkdpop/zkdpop-go/pkg/storage"
)

func setupTestHandlers(t *testing.T) *Handlers {
	store := storage.NewMemoryStore()
	crv := curve.NewSecp256k1()
	
	// Generate test signing key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	
	tokenSigner, err := jwtpkg.NewES256Signer(privKey, "test-key", "https://auth.test.com")
	if err != nil {
		t.Fatalf("failed to create token signer: %v", err)
	}
	
	replayStore := dpop.NewInMemoryReplayStore(5*time.Minute)
	
	config := Config{
		Issuer:     "https://auth.test.com",
		Audience:   "test-api",
		TokenTTL:   5 * time.Minute,
		SessionTTL: 2 * time.Minute,
	}
	
	return NewHandlers(store, crv, tokenSigner, replayStore, config)
}

func generateTestDPoPToken(t *testing.T, method, url string, privKey *ecdsa.PrivateKey) string {
	// Convert private key to JWK
	jwk, err := dpop.PublicKeyToJWK(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to convert to JWK: %v", err)
	}
	
	// Create DPoP claims
	claims := jwt.MapClaims{
		"htm": method,
		"htu": url,
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	
	// Add JWK to header
	jwkMap := map[string]interface{}{
		"kty": jwk.Kty,
		"crv": jwk.Crv,
		"x":   jwk.X,
		"y":   jwk.Y,
		"use": jwk.Use,
	}
	token.Header["jwk"] = jwkMap

	// Sign token
	dpopProof, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign DPoP proof: %v", err)
	}
	
	return dpopProof
}

func TestHandlers_Register(t *testing.T) {
	handlers := setupTestHandlers(t)
	
	// Generate test key pair
	crv := curve.NewSecp256k1()
	scalar, _ := crv.GenerateScalar()
	point := crv.ScalarBaseMult(scalar)
	pkBytes := point.Bytes()
	pkHex := encodeHex(pkBytes)
	
	t.Run("ValidRegistration", func(t *testing.T) {
		reqBody := RegisterRequest{
			PK:   pkHex,
			Meta: map[string]interface{}{"name": "test-user"},
		}
		
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		
		rr := httptest.NewRecorder()
		handlers.Register(rr, req)
		
		if rr.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
		}
		
		// Check user was created
		user, err := handlers.store.GetUser(pkHex)
		if err != nil {
			t.Errorf("user should be created: %v", err)
		}
		if user.Status != "active" {
			t.Errorf("user should be active, got %s", user.Status)
		}
	})
	
	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/register", strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		
		rr := httptest.NewRecorder()
		handlers.Register(rr, req)
		
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rr.Code)
		}
	})
	
	t.Run("InvalidPublicKey", func(t *testing.T) {
		reqBody := RegisterRequest{PK: "invalid-hex"}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		
		rr := httptest.NewRecorder()
		handlers.Register(rr, req)
		
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rr.Code)
		}
	})
	
	t.Run("DuplicateRegistration", func(t *testing.T) {
		// Register user first
		reqBody := RegisterRequest{PK: pkHex}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		
		rr := httptest.NewRecorder()
		handlers.Register(rr, req)
		
		// Try to register again
		rr2 := httptest.NewRecorder()
		req2 := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		req2.Header.Set("Content-Type", "application/json")
		handlers.Register(rr2, req2)
		
		if rr2.Code != http.StatusConflict {
			t.Errorf("expected status 409, got %d", rr2.Code)
		}
	})
	
	t.Run("BannedPublicKey", func(t *testing.T) {
		// Ban the key first
		handlers.store.AddToDenylist(pkHex)
		
		reqBody := RegisterRequest{PK: pkHex}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		
		rr := httptest.NewRecorder()
		handlers.Register(rr, req)
		
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status 403, got %d", rr.Code)
		}
	})
}

func TestHandlers_StartCommit(t *testing.T) {
	handlers := setupTestHandlers(t)
	crv := curve.NewSecp256k1()
	
	// Generate test key pair
	scalar, _ := crv.GenerateScalar()
	point := crv.ScalarBaseMult(scalar)
	pkBytes := point.Bytes()
	pkHex := encodeHex(pkBytes)
	
	// Register user first
	handlers.store.CreateUser(pkHex)
	
	// Generate commitment
	r, _ := crv.GenerateScalar()
	T := crv.ScalarBaseMult(r)
	TBytes := T.Bytes()
	THex := encodeHex(TBytes)
	
	t.Run("ValidStartCommit", func(t *testing.T) {
		// Generate DPoP key
		dpopPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		dpopToken := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/commit", dpopPrivKey)
		
		reqBody := StartCommitRequest{
			PK:     pkHex,
			T:      THex,
			Aud:    "test-api",
			Path:   "/auth/zk/commit",
			Method: "POST",
		}
		
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/commit", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		
		rr := httptest.NewRecorder()
		handlers.StartCommit(rr, req)
		
		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
		}
		
		var response StartCommitResponse
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Errorf("failed to decode response: %v", err)
		}
		
		if response.SessionID == "" {
			t.Error("session ID should not be empty")
		}
		if response.C == "" {
			t.Error("challenge should not be empty")
		}
		if response.Timeslice == "" {
			t.Error("timeslice should not be empty")
		}
		if response.ServerEphemeral == "" {
			t.Error("server ephemeral should not be empty")
		}
	})
	
	t.Run("MissingDPoP", func(t *testing.T) {
		reqBody := StartCommitRequest{
			PK:     pkHex,
			T:      THex,
			Aud:    "test-api",
			Path:   "/auth/zk/commit",
			Method: "POST",
		}
		
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/commit", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		
		rr := httptest.NewRecorder()
		handlers.StartCommit(rr, req)
		
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})
	
	t.Run("UserNotFound", func(t *testing.T) {
		dpopPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		dpopToken := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/commit", dpopPrivKey)
		
		reqBody := StartCommitRequest{
			PK:     "nonexistent-key",
			T:      THex,
			Aud:    "test-api",
			Path:   "/auth/zk/commit",
			Method: "POST",
		}
		
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/commit", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		
		rr := httptest.NewRecorder()
		handlers.StartCommit(rr, req)
		
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rr.Code)
		}
	})
	
	t.Run("InvalidCommitmentFormat", func(t *testing.T) {
		dpopPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		dpopToken := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/commit", dpopPrivKey)
		
		reqBody := StartCommitRequest{
			PK:     pkHex,
			T:      "invalid-hex",
			Aud:    "test-api",
			Path:   "/auth/zk/commit",
			Method: "POST",
		}
		
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/commit", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		
		rr := httptest.NewRecorder()
		handlers.StartCommit(rr, req)
		
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rr.Code)
		}
	})
	
	t.Run("InactiveUser", func(t *testing.T) {
		// Create inactive user
		inactiveKey := "inactive-key"
		handlers.store.CreateUser(inactiveKey)
		handlers.store.UpdateUserStatus(inactiveKey, "inactive")
		
		dpopPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		dpopToken := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/commit", dpopPrivKey)
		
		reqBody := StartCommitRequest{
			PK:     inactiveKey,
			T:      THex,
			Aud:    "test-api",
			Path:   "/auth/zk/commit",
			Method: "POST",
		}
		
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/commit", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		
		rr := httptest.NewRecorder()
		handlers.StartCommit(rr, req)
		
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status 403, got %d", rr.Code)
		}
	})
}

func TestHandlers_Complete(t *testing.T) {
	handlers := setupTestHandlers(t)
	crv := curve.NewSecp256k1()
	
	// Generate test key pair
	scalar, _ := crv.GenerateScalar()
	point := crv.ScalarBaseMult(scalar)
	pkBytes := point.Bytes()
	pkHex := encodeHex(pkBytes)
	
	// Register user
	handlers.store.CreateUser(pkHex)
	
	// Helper to create a fresh session
	createSession := func() (string, *ecdsa.PrivateKey, string) {
		dpopPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		dpopToken := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/commit", dpopPrivKey)
		
		// Generate commitment
		r, _ := crv.GenerateScalar()
		T := crv.ScalarBaseMult(r)
		TBytes := T.Bytes()
		THex := encodeHex(TBytes)
		
		startReq := StartCommitRequest{
			PK:     pkHex,
			T:      THex,
			Aud:    "test-api",
			Path:   "/auth/zk/commit",
			Method: "POST",
		}
		
		body, _ := json.Marshal(startReq)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/commit", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		
		rr := httptest.NewRecorder()
		handlers.StartCommit(rr, req)
		
		var startResp StartCommitResponse
		if rr.Code != http.StatusOK {
			t.Skipf("StartCommit failed with status %d: %s", rr.Code, rr.Body.String())
		}
		json.NewDecoder(rr.Body).Decode(&startResp)
		
		// Compute response using Schnorr protocol: s = r + c * x (mod order)
		cBytes, err := decodeHex(startResp.C)
		if err != nil || len(cBytes) == 0 {
			t.Skip("Failed to decode challenge")
		}
		c, _ := crv.ParseScalar(cBytes)
		
		// Calculate s = r + c * scalar (mod order)
		order := crv.Order()
		rBig := r.BigInt()
		cBig := c.BigInt()
		scalarBig := scalar.BigInt()
		
		// s = r + (c * scalar) mod order
		temp := new(big.Int).Mul(cBig, scalarBig)
		temp.Mod(temp, order)
		sBig := new(big.Int).Add(rBig, temp)
		sBig.Mod(sBig, order)
		
		// Convert back to 32-byte representation
		sBytes := make([]byte, 32)
		sBig.FillBytes(sBytes)
		sHex := encodeHex(sBytes)
		
		return startResp.SessionID, dpopPrivKey, sHex
	}
	
	t.Run("ValidComplete", func(t *testing.T) {
		sessionID, dpopPrivKey, sHex := createSession()
		
		// Create new DPoP proof for complete request  
		dpopToken2 := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/complete", dpopPrivKey)
		
		completeReq := CompleteRequest{
			SessionID: sessionID,
			S:         sHex,
		}
		
		body, _ := json.Marshal(completeReq)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken2)
		
		rr := httptest.NewRecorder()
		handlers.Complete(rr, req)
		
		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
		}
		
		var response CompleteResponse
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Errorf("failed to decode response: %v", err)
		}
		
		if response.AccessToken == "" {
			t.Error("access token should not be empty")
		}
		if response.ExpiresIn <= 0 {
			t.Error("expires_in should be positive")
		}
	})
	
	t.Run("SessionNotFound", func(t *testing.T) {
		_, dpopPrivKey, sHex := createSession()
		dpopToken2 := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/complete", dpopPrivKey)
		
		completeReq := CompleteRequest{
			SessionID: "nonexistent-session",
			S:         sHex,
		}
		
		body, _ := json.Marshal(completeReq)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken2)
		
		rr := httptest.NewRecorder()
		handlers.Complete(rr, req)
		
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rr.Code)
		}
	})
	
	t.Run("InvalidResponse", func(t *testing.T) {
		sessionID, dpopPrivKey, _ := createSession()
		dpopToken2 := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/complete", dpopPrivKey)
		
		completeReq := CompleteRequest{
			SessionID: sessionID,
			S:         "invalid-response",
		}
		
		body, _ := json.Marshal(completeReq)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken2)
		
		rr := httptest.NewRecorder()
		handlers.Complete(rr, req)
		
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})
	
	t.Run("DPoPKeyMismatch", func(t *testing.T) {
		sessionID, _, sHex := createSession()
		
		// Create DPoP proof with different key
		differentPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		dpopToken2 := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/complete", differentPrivKey)
		
		completeReq := CompleteRequest{
			SessionID: sessionID,
			S:         sHex,
		}
		
		body, _ := json.Marshal(completeReq)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken2)
		
		rr := httptest.NewRecorder()
		handlers.Complete(rr, req)
		
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 for DPoP key mismatch, got %d", rr.Code)
		}
	})
	
	t.Run("ExpiredSession", func(t *testing.T) {
		// Create an expired session manually
		dpopPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		dpopToken := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/complete", dpopPrivKey)
		
		// Create a dummy request to get the JKT from DPoP verification
		dummyReq := httptest.NewRequest("POST", "http://example.com/auth/zk/complete", nil)
		dummyReq.Header.Set("DPoP", dpopToken)
		
		// Create a minimal replay store for DPoP verification
		dummyReplayStore := dpop.NewInMemoryReplayStore(5*time.Minute)
		dpopResult, _ := dpop.VerifyDPoP(dummyReq, dummyReplayStore)
		jkt := dpopResult.JKT
		
		// Generate commitment  
		r, _ := crv.GenerateScalar()
		T := crv.ScalarBaseMult(r)
		TBytes := T.Bytes()
		
		// Generate challenge
		c, _ := crv.GenerateScalar()
		
		// Create expired session (5 minutes ago)
		expiredSessionID := "expired-session"
		expiredSession := &storage.ZKSession{
			ID:              expiredSessionID,
			PK:              pkHex,
			T:               TBytes,
			C:               c.Bytes(),
			Timeslice:       time.Now().Add(-5 * time.Minute), // 5 minutes ago
			ServerEphemeral: []byte("test-ephemeral"),
			JKT:             jkt,
			Used:            false,
		}
		
		handlers.store.CreateSession(expiredSession)
		
		// Compute valid response for this challenge
		order := crv.Order()
		rBig := r.BigInt()
		cBig := c.BigInt()
		scalarBig := scalar.BigInt()
		
		temp := new(big.Int).Mul(cBig, scalarBig)
		temp.Mod(temp, order)
		sBig := new(big.Int).Add(rBig, temp)
		sBig.Mod(sBig, order)
		
		sBytes := make([]byte, 32)
		sBig.FillBytes(sBytes)
		sHex := encodeHex(sBytes)
		
		completeReq := CompleteRequest{
			SessionID: expiredSessionID,
			S:         sHex,
		}
		
		body, _ := json.Marshal(completeReq)
		req := httptest.NewRequest("POST", "http://example.com/auth/zk/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken) // Use same token
		
		rr := httptest.NewRecorder()
		handlers.Complete(rr, req)
		
		if rr.Code != http.StatusGone {
			t.Errorf("expected status 410 for expired session, got %d", rr.Code)
		}
	})
}

func TestHandlers_JWKS(t *testing.T) {
	handlers := setupTestHandlers(t)
	
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	
	handlers.JWKS(rr, req)
	
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected content-type application/json, got %s", contentType)
	}
	
	cacheControl := rr.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "max-age=300") {
		t.Errorf("expected cache control with max-age=300, got %s", cacheControl)
	}
	
	var jwks map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&jwks); err != nil {
		t.Errorf("failed to decode JWKS: %v", err)
	}
	
	keys, ok := jwks["keys"]
	if !ok {
		t.Error("JWKS should have keys field")
	}
	
	keysList, ok := keys.([]interface{})
	if !ok || len(keysList) == 0 {
		t.Error("JWKS should have at least one key")
	}
}

func TestUtilityFunctions(t *testing.T) {
	t.Run("decodeHex", func(t *testing.T) {
		// Test hex decoding
		input := "deadbeef"
		expected := []byte{0xde, 0xad, 0xbe, 0xef}
		
		result, err := decodeHex(input)
		if err != nil {
			t.Errorf("failed to decode hex: %v", err)
		}
		
		if !bytes.Equal(result, expected) {
			t.Errorf("hex decode mismatch: expected %x, got %x", expected, result)
		}
		
		// Test 0x prefix removal
		result2, err := decodeHex("0x" + input)
		if err != nil {
			t.Errorf("failed to decode hex with 0x prefix: %v", err)
		}
		
		if !bytes.Equal(result2, expected) {
			t.Errorf("hex decode with prefix mismatch: expected %x, got %x", expected, result2)
		}
		
		// Test base64url fallback
		base64Input := "SGVsbG8gV29ybGQ"
		expected2 := []byte("Hello World")
		
		result3, err := decodeHex(base64Input)
		if err != nil {
			t.Errorf("failed to decode base64url: %v", err)
		}
		
		if !bytes.Equal(result3, expected2) {
			t.Errorf("base64url decode mismatch: expected %s, got %s", expected2, result3)
		}
	})
	
	t.Run("encodeHex", func(t *testing.T) {
		input := []byte{0xde, 0xad, 0xbe, 0xef}
		expected := "deadbeef"
		
		result := encodeHex(input)
		if result != expected {
			t.Errorf("hex encode mismatch: expected %s, got %s", expected, result)
		}
	})
	
	t.Run("isHex", func(t *testing.T) {
		validHex := []string{"deadbeef", "DEADBEEF", "1234567890abcdef", ""}
		invalidHex := []string{"xyz", "hello", "123g", "SGVsbG8gV29ybGQ"}
		
		for _, h := range validHex {
			if !isHex(h) {
				t.Errorf("'%s' should be valid hex", h)
			}
		}
		
		for _, h := range invalidHex {
			if isHex(h) {
				t.Errorf("'%s' should not be valid hex", h)
			}
		}
	})
	
	t.Run("hexToByte", func(t *testing.T) {
		tests := []struct {
			input    byte
			expected byte
		}{
			{'0', 0}, {'9', 9}, {'a', 10}, {'f', 15},
			{'A', 10}, {'F', 15},
		}
		
		for _, test := range tests {
			result := hexToByte(test.input)
			if result != test.expected {
				t.Errorf("hexToByte(%c) = %d, expected %d", test.input, result, test.expected)
			}
		}
	})
}

func TestConfig(t *testing.T) {
	config := Config{
		Issuer:     "https://auth.example.com",
		Audience:   "test-api",
		TokenTTL:   5 * time.Minute,
		SessionTTL: 2 * time.Minute,
	}
	
	if config.Issuer != "https://auth.example.com" {
		t.Errorf("wrong issuer: %s", config.Issuer)
	}
	
	if config.TokenTTL != 5*time.Minute {
		t.Errorf("wrong token TTL: %v", config.TokenTTL)
	}
}