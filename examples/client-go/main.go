package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/zkdpop/zkdpop-go/pkg/crypto/curve"
	"github.com/zkdpop/zkdpop-go/pkg/crypto/schnorr"
	"github.com/zkdpop/zkdpop-go/pkg/dpop"
)

func main() {
	// Command line flags
	var (
		authServer = flag.String("auth-server", "http://localhost:8080", "Auth server base URL")
		apiServer  = flag.String("api-server", "http://localhost:8081", "API server base URL")
		audience   = flag.String("audience", "zkdpop-api", "JWT audience")
		curveName  = flag.String("curve", "secp256k1", "Curve to use (secp256k1|ristretto255)")
	)
	flag.Parse()

	log.Println("zkDPoP Go Client Demo")
	log.Println("====================")
	log.Printf("Auth Server: %s", *authServer)
	log.Printf("API Server: %s", *apiServer)
	log.Printf("Audience: %s", *audience)
	log.Println()

	crv, err := curve.FromName(*curveName)
	if err != nil {
		log.Fatalf("Unsupported curve %q: %v", *curveName, err)
	}

	client := &ZKClient{
		AuthServerURL: *authServer,
		APIServerURL:  *apiServer,
		Audience:      *audience,
		HTTPClient:    &http.Client{Timeout: 30 * time.Second},
		curve:         crv,
	}

	// Run the demo
	if err := client.RunDemo(); err != nil {
		log.Fatalf("Demo failed: %v", err)
	}

	log.Println("✅ Demo completed successfully!")
}

// ZKClient demonstrates zkDPoP authentication flow
type ZKClient struct {
	AuthServerURL string
	APIServerURL  string
	Audience      string
	HTTPClient    *http.Client

	// Identity key pair for ZK authentication
	identityPrivateKey curve.Scalar
	identityPublicKey  []byte

	// DPoP key pair for proof-of-possession
	dpopPrivateKey *ecdsa.PrivateKey
	dpopJWK        *dpop.JWK

	// Session state
	accessToken          string
	commitmentRandomness curve.Scalar
	curve                curve.Curve
}

// RunDemo executes the complete zkDPoP authentication flow
func (c *ZKClient) RunDemo() error {
	// Step 1: Initialize cryptographic components
	log.Println("Step 1: Initializing cryptographic components...")
	if err := c.initializeCrypto(); err != nil {
		return fmt.Errorf("failed to initialize crypto: %w", err)
	}
	log.Printf("  ✅ Curve: %s", c.curve.Name())
	log.Printf("  ✅ Identity public key: %x", c.identityPublicKey[:8])
	log.Printf("  ✅ DPoP JWK thumbprint: %s", c.computeJWKThumbprint()[:16])

	// Step 2: Register user
	log.Println("\nStep 2: Registering user...")
	if err := c.register(); err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}
	log.Println("  ✅ User registered successfully")

	// Step 3: Perform ZK login
	log.Println("\nStep 3: Performing ZK login...")
	if err := c.zkLogin(); err != nil {
		return fmt.Errorf("failed to ZK login: %w", err)
	}
	log.Println("  ✅ ZK login completed successfully")
	log.Printf("  ✅ Received JWT token (expires in ~5 min)")

	// Step 4: Test API endpoints
	log.Println("\nStep 4: Testing API endpoints...")
	if err := c.testAPIEndpoints(); err != nil {
		return fmt.Errorf("failed to test APIs: %w", err)
	}
	log.Println("  ✅ All API tests passed")

	return nil
}

// initializeCrypto sets up the identity and DPoP key pairs
func (c *ZKClient) initializeCrypto() error {
	// Ensure curve is configured
	if c.curve == nil {
		c.curve = curve.NewSecp256k1()
	}

	// Generate identity key pair for ZK authentication
	identityPrivateKey, err := c.curve.GenerateScalar()
	if err != nil {
		return fmt.Errorf("failed to generate identity private key: %w", err)
	}
	c.identityPrivateKey = identityPrivateKey

	// Compute public key
	publicKeyPoint := c.curve.ScalarBaseMult(identityPrivateKey)
	c.identityPublicKey = publicKeyPoint.Bytes()

	// Generate DPoP key pair (ECDSA P-256 for JWTs)
	dpopPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate DPoP key: %w", err)
	}
	c.dpopPrivateKey = dpopPrivateKey

	// Convert to JWK
	jwk, err := dpop.PublicKeyToJWK(&dpopPrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to convert DPoP key to JWK: %w", err)
	}
	c.dpopJWK = jwk

	return nil
}

// register creates a new user account
func (c *ZKClient) register() error {
	reqBody := map[string]interface{}{
		"pk": encodeHex(c.identityPublicKey),
	}

	respBody, err := c.makeJSONRequest("POST", "/register", reqBody, false)
	if err != nil {
		return err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if status, ok := resp["status"].(string); !ok || status != "created" {
		return fmt.Errorf("unexpected registration response: %v", resp)
	}

	return nil
}

// zkLogin performs the two-phase ZK authentication
func (c *ZKClient) zkLogin() error {
	// Phase 1: Commit
	log.Println("  → Phase 1: Commitment...")
	sessionID, challenge, timeslice, serverEphemeral, err := c.zkCommit()
	if err != nil {
		return fmt.Errorf("commit phase failed: %w", err)
	}

	// Phase 2: Response
	log.Println("  → Phase 2: Response...")
	if err := c.zkComplete(sessionID, challenge, timeslice, serverEphemeral); err != nil {
		return fmt.Errorf("complete phase failed: %w", err)
	}

	return nil
}

// zkCommit performs the commitment phase
func (c *ZKClient) zkCommit() (string, []byte, time.Time, []byte, error) {
	// Generate random commitment
	T, r, err := schnorr.GenerateCommitment(c.curve)
	if err != nil {
		return "", nil, time.Time{}, nil, fmt.Errorf("failed to generate commitment: %w", err)
	}

	// Prepare request
	reqBody := map[string]interface{}{
		"pk":     encodeHex(c.identityPublicKey),
		"T":      encodeHex(T),
		"aud":    c.Audience,
		"path":   "/auth/zk/complete",
		"method": "POST",
	}

	// Make request with DPoP
	respBody, err := c.makeJSONRequest("POST", "/auth/zk/commit", reqBody, true)
	if err != nil {
		return "", nil, time.Time{}, nil, err
	}

	// Parse response
	var resp struct {
		SessionID       string `json:"session_id"`
		C               string `json:"c"`
		Timeslice       string `json:"timeslice"`
		ServerEphemeral string `json:"server_ephemeral"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", nil, time.Time{}, nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Parse timeslice
	timeslice, err := time.Parse(time.RFC3339, resp.Timeslice)
	if err != nil {
		return "", nil, time.Time{}, nil, fmt.Errorf("invalid timeslice: %w", err)
	}

	// Decode challenge and server ephemeral
	challenge, err := decodeHex(resp.C)
	if err != nil {
		return "", nil, time.Time{}, nil, fmt.Errorf("invalid challenge: %w", err)
	}

	serverEphemeral, err := decodeHex(resp.ServerEphemeral)
	if err != nil {
		return "", nil, time.Time{}, nil, fmt.Errorf("invalid server ephemeral: %w", err)
	}

	// Store commitment randomness for response phase
	c.commitmentRandomness = r

	return resp.SessionID, challenge, timeslice, serverEphemeral, nil
}

// zkComplete performs the response phase
func (c *ZKClient) zkComplete(sessionID string, challenge []byte, timeslice time.Time, serverEphemeral []byte) error {
	// Parse challenge scalar
	challengeScalar, err := c.curve.ParseScalar(challenge)
	if err != nil {
		return fmt.Errorf("invalid challenge scalar: %w", err)
	}

	// Compute response: s = r + c*x
	response, err := schnorr.ComputeResponse(c.curve, c.commitmentRandomness, challengeScalar, c.identityPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to compute response: %w", err)
	}

	// Prepare request
	reqBody := map[string]interface{}{
		"session_id": sessionID,
		"s":          encodeHex(response.Bytes()),
	}

	// Make request with DPoP (same key as commit phase)
	respBody, err := c.makeJSONRequest("POST", "/auth/zk/complete", reqBody, true)
	if err != nil {
		return err
	}

	// Parse response
	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	c.accessToken = resp.AccessToken
	log.Printf("    Received token expires in %d seconds", resp.ExpiresIn)

	return nil
}

// testAPIEndpoints tests various protected endpoints
func (c *ZKClient) testAPIEndpoints() error {
	// Test profile endpoint
	log.Println("  → Testing /api/profile...")
	if err := c.testEndpoint("GET", "/api/profile"); err != nil {
		return fmt.Errorf("profile test failed: %w", err)
	}

	// Test orders endpoint
	log.Println("  → Testing /api/orders...")
	if err := c.testEndpoint("GET", "/api/orders"); err != nil {
		return fmt.Errorf("orders test failed: %w", err)
	}

	// Test secure endpoint (requires Schnorr ZK)
	log.Println("  → Testing /api/secure/data...")
	if err := c.testEndpoint("GET", "/api/secure/data"); err != nil {
		return fmt.Errorf("secure test failed: %w", err)
	}

	// Test secp256k1 endpoint
	log.Println("  → Testing /api/secp256k1/bitcoin-data...")
	if err := c.testEndpoint("GET", "/api/secp256k1/bitcoin-data"); err != nil {
		return fmt.Errorf("secp256k1 test failed: %w", err)
	}

	return nil
}

// testEndpoint makes an authenticated API call
func (c *ZKClient) testEndpoint(method, path string) error {
	// Create request
	reqURL := c.APIServerURL + path
	req, err := http.NewRequest(method, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add JWT token
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	// Add DPoP proof
	dpopProof, err := c.generateDPoPProof(method, reqURL)
	if err != nil {
		return fmt.Errorf("failed to generate DPoP proof: %w", err)
	}
	req.Header.Set("DPoP", dpopProof)

	// Make request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API call failed: %d %s", resp.StatusCode, string(body))
	}

	// Parse and display response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err == nil {
		log.Printf("    Response: %v", result["message"])
	}

	return nil
}

// makeJSONRequest makes an HTTP request with JSON body
func (c *ZKClient) makeJSONRequest(method, path string, body interface{}, withDPoP bool) ([]byte, error) {
	// Serialize body
	var reqBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		reqBody = bytes.NewReader(bodyBytes)
	}

	// Create request
	reqURL := c.AuthServerURL + path
	req, err := http.NewRequest(method, reqURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add DPoP proof if requested
	if withDPoP {
		dpopProof, err := c.generateDPoPProof(method, reqURL)
		if err != nil {
			return nil, fmt.Errorf("failed to generate DPoP proof: %w", err)
		}
		req.Header.Set("DPoP", dpopProof)
	}

	// Make request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// generateDPoPProof creates a DPoP proof JWT
func (c *ZKClient) generateDPoPProof(method, urlStr string) (string, error) {
	// Parse URL (validation only)
	if _, err := url.Parse(urlStr); err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Create claims
	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"htm": method,
		"htu": urlStr,
		"iat": now,
		"jti": uuid.New().String(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Add JWK to header
	jwkMap := map[string]interface{}{
		"kty": c.dpopJWK.Kty,
		"crv": c.dpopJWK.Crv,
		"x":   c.dpopJWK.X,
		"y":   c.dpopJWK.Y,
		"use": c.dpopJWK.Use,
	}
	token.Header["jwk"] = jwkMap

	// Sign token
	tokenString, err := token.SignedString(c.dpopPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign DPoP proof: %w", err)
	}

	return tokenString, nil
}

// computeJWKThumbprint computes the SHA-256 thumbprint of the DPoP JWK
func (c *ZKClient) computeJWKThumbprint() string {
	canonical := map[string]interface{}{
		"crv": c.dpopJWK.Crv,
		"kty": c.dpopJWK.Kty,
		"x":   c.dpopJWK.X,
		"y":   c.dpopJWK.Y,
	}

	canonicalJSON, _ := json.Marshal(canonical)
	hash := sha256.Sum256(canonicalJSON)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// Utility functions
func encodeHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, c := range b {
		s[i*2] = hexChars[c>>4]
		s[i*2+1] = hexChars[c&0x0f]
	}
	return string(s)
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex string has odd length")
	}

	bytes := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high, err := strconv.ParseUint(s[i:i+1], 16, 8)
		if err != nil {
			return nil, err
		}
		low, err := strconv.ParseUint(s[i+1:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		bytes[i/2] = byte(high<<4 | low)
	}

	return bytes, nil
}
