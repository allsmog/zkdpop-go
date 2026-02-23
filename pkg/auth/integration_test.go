package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/allsmog/zkdpop-go/pkg/crypto/curve"
	"github.com/allsmog/zkdpop-go/pkg/crypto/schnorr"
	"github.com/allsmog/zkdpop-go/pkg/dpop"
	jwtpkg "github.com/allsmog/zkdpop-go/pkg/jwt"
	"github.com/allsmog/zkdpop-go/pkg/storage"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// TestFullAuthenticationFlow tests the complete ZK authentication flow end-to-end
func TestFullAuthenticationFlow(t *testing.T) {
	// Setup
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
		Issuer:     "test-issuer",
		Audience:   "test-audience", 
		TokenTTL:   time.Hour,
		SessionTTL: 2 * time.Minute,
	}
	
	handlers := NewHandlers(store, crv, tokenSigner, replayStore, config)
	
	// Generate test keypair
	scalar, err := crv.GenerateScalar()
	if err != nil {
		t.Fatal(err)
	}
	
	pubKey := crv.ScalarBaseMult(scalar)
	pubKeyBytes := pubKey.Bytes()
	pkHex := encodeHex(pubKeyBytes)
	
	// Generate DPoP keypair (ECDSA for testing)
	dpopPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	
	t.Run("CompleteFlow", func(t *testing.T) {
		// Step 1: Register user
		regReq := RegisterRequest{
			PK:   pkHex,
			Meta: map[string]interface{}{"test": true},
		}
		regBody, _ := json.Marshal(regReq)
		
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(regBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		handlers.Register(w, req)
		
		if w.Code != http.StatusCreated {
			t.Fatalf("Registration failed: %d %s", w.Code, w.Body.String())
		}
		
		// Step 2: Start commit phase
		// Generate commitment
		r, err := crv.GenerateScalar()
		if err != nil {
			t.Fatal(err)
		}
		
		T := crv.ScalarBaseMult(r)
		TBytes := T.Bytes()
		
		startReq := StartCommitRequest{
			PK:     pkHex,
			T:      encodeHex(TBytes),
			Aud:    "test-audience",
			Path:   "/auth/zk/commit",
			Method: "POST",
		}
		startBody, _ := json.Marshal(startReq)
		
		// Generate DPoP token for commit
		dpopToken := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/commit", dpopPrivKey)
		
		req = httptest.NewRequest("POST", "/auth/zk/commit", bytes.NewReader(startBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		w = httptest.NewRecorder()
		
		handlers.StartCommit(w, req)
		
		if w.Code != http.StatusOK {
			t.Fatalf("StartCommit failed: %d %s", w.Code, w.Body.String())
		}
		
		var startResp StartCommitResponse
		if err := json.NewDecoder(w.Body).Decode(&startResp); err != nil {
			t.Fatal(err)
		}
		
		// Step 3: Complete authentication
		// Derive context and challenge
		parsedTime, err := time.Parse(time.RFC3339, startResp.Timeslice)
		if err != nil {
			t.Fatal(err)
		}
		
		serverEphemeral, err := decodeHex(startResp.ServerEphemeral)
		if err != nil {
			t.Fatal(err)
		}
		
		ctx := schnorr.DeriveContext("test-audience", "/auth/zk/commit", "POST", 
			parsedTime.Format(time.RFC3339), serverEphemeral)
		
		challenge, err := schnorr.DeriveChallenge(crv, TBytes, pubKeyBytes, ctx)
		if err != nil {
			t.Fatal(err)
		}
		
		// Verify challenge matches response
		expectedChallenge, err := decodeHex(startResp.C)
		if err != nil {
			t.Fatal(err)
		}
		
		if !bytes.Equal(challenge, expectedChallenge) {
			t.Fatalf("Challenge mismatch: expected %x, got %x", expectedChallenge, challenge)
		}
		
		// Compute response: s = r + c*sk using ComputeResponse
		cScalar, err := crv.ParseScalar(challenge)
		if err != nil {
			t.Fatal(err)
		}
		
		s, err := schnorr.ComputeResponse(crv, r, cScalar, scalar)
		if err != nil {
			t.Fatal(err)
		}
		sBytes := s.Bytes()
		
		completeReq := CompleteRequest{
			SessionID: startResp.SessionID,
			S:         encodeHex(sBytes),
		}
		completeBody, _ := json.Marshal(completeReq)
		
		// Generate DPoP token for complete (same key)
		dpopToken = generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/complete", dpopPrivKey)
		
		req = httptest.NewRequest("POST", "/auth/zk/complete", bytes.NewReader(completeBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		w = httptest.NewRecorder()
		
		handlers.Complete(w, req)
		
		if w.Code != http.StatusOK {
			t.Fatalf("Complete failed: %d %s", w.Code, w.Body.String())
		}
		
		var completeResp CompleteResponse
		if err := json.NewDecoder(w.Body).Decode(&completeResp); err != nil {
			t.Fatal(err)
		}
		
		// Step 4: Verify issued token
		if completeResp.AccessToken == "" {
			t.Fatal("No access token returned")
		}
		
		if completeResp.ExpiresIn <= 0 {
			t.Fatal("Invalid expires_in value")
		}
		
		// Parse and validate JWT
		tokenParts := strings.Split(completeResp.AccessToken, ".")
		if len(tokenParts) != 3 {
			t.Fatal("Invalid JWT format")
		}
		
		// Verify signature using token signer's JWKS
		jwks := tokenSigner.JWKS()
		
		_, err = jws.Verify([]byte(completeResp.AccessToken), jws.WithKeySet(jwks))
		if err != nil {
			t.Fatalf("JWT signature verification failed: %v", err)
		}
		
		// Verify claims
		verifier := jwtpkg.NewJWTVerifier(jwks)
		claims, err := verifier.Verify(completeResp.AccessToken, "test-audience")
		if err != nil {
			t.Fatalf("JWT verification failed: %v", err)
		}
		
		// Check cnf.jkt binding
		if claims.Cnf == nil || claims.Cnf.JKT == "" {
			t.Fatal("Missing cnf.jkt claim")
		}
		
		// Check ZK claims
		if claims.ZK == nil {
			t.Fatal("Missing ZK claims")
		}
		
		if claims.ZK.Scheme != "schnorr-id" {
			t.Errorf("Expected ZK scheme 'schnorr-id', got '%s'", claims.ZK.Scheme)
		}
		
		if claims.ZK.Group != "secp256k1" {
			t.Errorf("Expected ZK group 'secp256k1', got '%s'", claims.ZK.Group)
		}
		
		// Verify ZK proof data
		if claims.ZK.THash == "" || claims.ZK.Challenge == "" {
			t.Fatal("Missing ZK proof data")
		}
		
		// Parse ZK proof components (base64 encoded)
		zkC, err := base64.StdEncoding.DecodeString(claims.ZK.Challenge)
		if err != nil {
			t.Fatalf("Invalid ZK Challenge: %v", err)
		}
		
		// Verify challenge matches 
		if !bytes.Equal(zkC, challenge) {
			t.Fatal("ZK Challenge mismatch")
		}
		
		// Note: THash is a hash of T, not T itself, so we skip direct comparison
		
		t.Log("✓ Complete authentication flow successful")
		t.Logf("✓ Issued JWT with cnf.jkt: %s", claims.Cnf.JKT)
		t.Logf("✓ ZK scheme: %s, group: %s", claims.ZK.Scheme, claims.ZK.Group)
	})
	
	t.Run("FlowWithInvalidProof", func(t *testing.T) {
		// Register user
		regReq := RegisterRequest{PK: pkHex}
		regBody, _ := json.Marshal(regReq)
		
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(regBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handlers.Register(w, req)
		
		// Start commit
		r2, err := crv.GenerateScalar()
		if err != nil {
			t.Fatal(err)
		}
		
		T2 := crv.ScalarBaseMult(r2)
		T2Bytes := T2.Bytes()
		
		startReq := StartCommitRequest{
			PK:     pkHex,
			T:      encodeHex(T2Bytes),
			Aud:    "test-audience",
			Path:   "/auth/zk/commit", 
			Method: "POST",
		}
		startBody, _ := json.Marshal(startReq)
		
		dpopToken := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/commit", dpopPrivKey)
		
		req = httptest.NewRequest("POST", "/auth/zk/commit", bytes.NewReader(startBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		w = httptest.NewRecorder()
		
		handlers.StartCommit(w, req)
		
		var startResp StartCommitResponse
		json.NewDecoder(w.Body).Decode(&startResp)
		
		// Complete with wrong response (use different scalar)
		wrongScalar, err := crv.GenerateScalar()
		if err != nil {
			t.Fatal(err)
		}
		
		wrongSBytes := wrongScalar.Bytes()
		
		completeReq := CompleteRequest{
			SessionID: startResp.SessionID,
			S:         encodeHex(wrongSBytes),
		}
		completeBody, _ := json.Marshal(completeReq)
		
		dpopToken = generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/complete", dpopPrivKey)
		
		req = httptest.NewRequest("POST", "/auth/zk/complete", bytes.NewReader(completeBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		w = httptest.NewRecorder()
		
		handlers.Complete(w, req)
		
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for invalid proof, got %d", w.Code)
		}
		
		if !strings.Contains(w.Body.String(), "invalid Schnorr proof") {
			t.Errorf("Expected 'invalid Schnorr proof' error, got: %s", w.Body.String())
		}
	})
	
	t.Run("FlowWithDPoPKeyMismatch", func(t *testing.T) {
		// Register user
		regReq := RegisterRequest{PK: pkHex}
		regBody, _ := json.Marshal(regReq)
		
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(regBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handlers.Register(w, req)
		
		// Start commit with one DPoP key
		r3, err := crv.GenerateScalar()
		if err != nil {
			t.Fatal(err)
		}
		
		T3 := crv.ScalarBaseMult(r3)
		T3Bytes := T3.Bytes()
		
		startReq := StartCommitRequest{
			PK:     pkHex,
			T:      encodeHex(T3Bytes),
			Aud:    "test-audience",
			Path:   "/auth/zk/commit",
			Method: "POST",
		}
		startBody, _ := json.Marshal(startReq)
		
		dpopToken := generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/commit", dpopPrivKey)
		
		req = httptest.NewRequest("POST", "/auth/zk/commit", bytes.NewReader(startBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		w = httptest.NewRecorder()
		
		handlers.StartCommit(w, req)
		
		var startResp StartCommitResponse
		json.NewDecoder(w.Body).Decode(&startResp)
		
		// Complete with different DPoP key
		differentDPoPKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		
		// Derive proper response
		parsedTime, err := time.Parse(time.RFC3339, startResp.Timeslice)
		if err != nil {
			t.Fatal(err)
		}
		
		serverEphemeral, err := decodeHex(startResp.ServerEphemeral)
		if err != nil {
			t.Fatal(err)
		}
		
		ctx := schnorr.DeriveContext("test-audience", "/auth/zk/commit", "POST",
			parsedTime.Format(time.RFC3339), serverEphemeral)
		
		challenge, err := schnorr.DeriveChallenge(crv, T3Bytes, pubKeyBytes, ctx)
		if err != nil {
			t.Fatal(err)
		}
		
		cScalar, err := crv.ParseScalar(challenge)
		if err != nil {
			t.Fatal(err)
		}
		
		s, err := schnorr.ComputeResponse(crv, r3, cScalar, scalar)
		if err != nil {
			t.Fatal(err)
		}
		sBytes := s.Bytes()
		
		completeReq := CompleteRequest{
			SessionID: startResp.SessionID,
			S:         encodeHex(sBytes),
		}
		completeBody, _ := json.Marshal(completeReq)
		
		// Use different DPoP key
		dpopToken = generateTestDPoPToken(t, "POST", "http://example.com/auth/zk/complete", differentDPoPKey)
		
		req = httptest.NewRequest("POST", "/auth/zk/complete", bytes.NewReader(completeBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopToken)
		w = httptest.NewRecorder()
		
		handlers.Complete(w, req)
		
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for DPoP key mismatch, got %d", w.Code)
		}
		
		if !strings.Contains(w.Body.String(), "DPoP key mismatch") {
			t.Errorf("Expected 'DPoP key mismatch' error, got: %s", w.Body.String())
		}
	})
}

// TestJWKSEndpoint tests the JWKS endpoint
func TestJWKSEndpoint(t *testing.T) {
	// Generate test signing key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	
	tokenSigner, err := jwtpkg.NewES256Signer(privKey, "test-key", "https://auth.test.com")
	if err != nil {
		t.Fatalf("failed to create token signer: %v", err)
	}
	
	handlers := NewHandlers(nil, nil, tokenSigner, nil, Config{})
	
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	
	handlers.JWKS(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected application/json content type")
	}
	
	if w.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Errorf("Expected cache control header")
	}
	
	// Check that response contains valid JSON
	var jwksResponse map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&jwksResponse); err != nil {
		t.Errorf("Failed to decode JWKS JSON: %v", err)
		return
	}
	
	// Check that keys array exists
	keys, ok := jwksResponse["keys"]
	if !ok {
		t.Error("JWKS response missing 'keys' field")
		return
	}
	
	keysArray, ok := keys.([]interface{})
	if !ok || len(keysArray) == 0 {
		t.Error("JWKS should contain at least one key")
	}
}