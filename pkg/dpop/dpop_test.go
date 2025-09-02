package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestComputeJWKThumbprint(t *testing.T) {
	// Test with known JWK
	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		Y:   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	}

	thumbprint := computeJWKThumbprint(jwk)

	// Should be consistent
	thumbprint2 := computeJWKThumbprint(jwk)
	if thumbprint != thumbprint2 {
		t.Error("thumbprint should be consistent")
	}

	// Should be base64url encoded
	_, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		t.Errorf("thumbprint should be valid base64url: %v", err)
	}

	// Different JWKs should produce different thumbprints
	jwk2 := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "different-x-coordinate-value-here",
		Y:   "different-y-coordinate-value-here",
	}

	thumbprint3 := computeJWKThumbprint(jwk2)
	if thumbprint == thumbprint3 {
		t.Error("different JWKs should produce different thumbprints")
	}
}

func TestJWKConversion(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to JWK
	jwk, err := PublicKeyToJWK(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to convert to JWK: %v", err)
	}

	// Verify JWK fields
	if jwk.Kty != "EC" {
		t.Errorf("expected kty 'EC', got %s", jwk.Kty)
	}

	if jwk.Crv != "P-256" {
		t.Errorf("expected crv 'P-256', got %s", jwk.Crv)
	}

	if jwk.X == "" || jwk.Y == "" {
		t.Error("X and Y coordinates should not be empty")
	}

	// Convert back to public key
	convertedKey, err := jwkToPublicKey(jwk)
	if err != nil {
		t.Fatalf("failed to convert back to public key: %v", err)
	}

	ecdsaKey, ok := convertedKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("converted key should be ECDSA public key")
	}

	// Should be the same key
	if privateKey.PublicKey.X.Cmp(ecdsaKey.X) != 0 || privateKey.PublicKey.Y.Cmp(ecdsaKey.Y) != 0 {
		t.Error("converted key should match original")
	}
}

func TestGenerateDPoPProof(t *testing.T) {
	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create JWK: %v", err)
	}

	// Create DPoP proof
	method := "POST"
	url := "https://api.example.com/protected"
	
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
	dpopProof, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign DPoP proof: %v", err)
	}

	// Verify we can parse it
	parsedToken, err := jwt.Parse(dpopProof, func(token *jwt.Token) (interface{}, error) {
		// Extract JWK from header
		jwkRaw := token.Header["jwk"].(map[string]interface{})
		jwkBytes, _ := json.Marshal(jwkRaw)
		
		var parsedJWK JWK
		json.Unmarshal(jwkBytes, &parsedJWK)
		
		return jwkToPublicKey(&parsedJWK)
	})

	if err != nil {
		t.Fatalf("failed to parse DPoP proof: %v", err)
	}

	if !parsedToken.Valid {
		t.Error("DPoP proof should be valid")
	}

	// Check claims
	mapClaims := parsedToken.Claims.(jwt.MapClaims)
	if mapClaims["htm"] != method {
		t.Errorf("expected htm %s, got %v", method, mapClaims["htm"])
	}

	if mapClaims["htu"] != url {
		t.Errorf("expected htu %s, got %v", url, mapClaims["htu"])
	}
}

func TestVerifyDPoP(t *testing.T) {
	// Setup replay store
	replayStore := NewInMemoryReplayStore(5 * time.Minute)

	// Generate key pair and JWK
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := PublicKeyToJWK(&privateKey.PublicKey)

	t.Run("ValidDPoP", func(t *testing.T) {
		// Create valid DPoP proof
		method := "GET"
		url := "https://api.example.com/test"
		jti := uuid.New().String()

		claims := jwt.MapClaims{
			"htm": method,
			"htu": url,
			"iat": time.Now().Unix(),
			"jti": jti,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["jwk"] = map[string]interface{}{
			"kty": jwk.Kty,
			"crv": jwk.Crv,
			"x":   jwk.X,
			"y":   jwk.Y,
			"use": jwk.Use,
		}

		dpopProof, _ := token.SignedString(privateKey)

		// Create HTTP request
		req := httptest.NewRequest(method, url, nil)
		req.Header.Set("DPoP", dpopProof)

		// Verify
		result, err := VerifyDPoP(req, replayStore)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}

		if result.JKT == "" {
			t.Error("JKT should not be empty")
		}

		if result.Claims.HTM != method {
			t.Errorf("expected HTM %s, got %s", method, result.Claims.HTM)
		}

		if result.Claims.HTU != url {
			t.Errorf("expected HTU %s, got %s", url, result.Claims.HTU)
		}
	})

	t.Run("MissingDPoP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		// No DPoP header

		_, err := VerifyDPoP(req, replayStore)
		if err == nil {
			t.Error("should fail without DPoP header")
		}
	})

	t.Run("MethodMismatch", func(t *testing.T) {
		// Create DPoP proof for POST
		claims := jwt.MapClaims{
			"htm": "POST",
			"htu": "https://api.example.com/test",
			"iat": time.Now().Unix(),
			"jti": uuid.New().String(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["jwk"] = map[string]interface{}{
			"kty": jwk.Kty,
			"crv": jwk.Crv,
			"x":   jwk.X,
			"y":   jwk.Y,
		}

		dpopProof, _ := token.SignedString(privateKey)

		// Create request for GET
		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		req.Header.Set("DPoP", dpopProof)

		_, err := VerifyDPoP(req, replayStore)
		if err == nil {
			t.Error("should fail with method mismatch")
		}
	})

	t.Run("Replay", func(t *testing.T) {
		method := "GET"
		url := "https://api.example.com/test"
		jti := uuid.New().String()

		// Create DPoP proof
		claims := jwt.MapClaims{
			"htm": method,
			"htu": url,
			"iat": time.Now().Unix(),
			"jti": jti,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["jwk"] = map[string]interface{}{
			"kty": jwk.Kty,
			"crv": jwk.Crv,
			"x":   jwk.X,
			"y":   jwk.Y,
		}

		dpopProof, _ := token.SignedString(privateKey)

		// First request should succeed
		req1 := httptest.NewRequest(method, url, nil)
		req1.Header.Set("DPoP", dpopProof)

		_, err := VerifyDPoP(req1, replayStore)
		if err != nil {
			t.Fatalf("first request should succeed: %v", err)
		}

		// Second request with same proof should fail
		req2 := httptest.NewRequest(method, url, nil)
		req2.Header.Set("DPoP", dpopProof)

		_, err = VerifyDPoP(req2, replayStore)
		if err == nil {
			t.Error("replay should be detected")
		}
	})
}

func TestInMemoryReplayStore(t *testing.T) {
	store := NewInMemoryReplayStore(100 * time.Millisecond)

	jkt := "test-jkt"
	jti := "test-jti"
	htm := "GET"
	htu := "https://example.com/test"
	minute := time.Now().Unix() / 60

	// First call should return false (not seen)
	if store.Seen(jkt, jti, htm, htu, minute) {
		t.Error("first call should return false")
	}

	// Second call should return true (seen)
	if !store.Seen(jkt, jti, htm, htu, minute) {
		t.Error("second call should return true")
	}

	// Wait for expiry and trigger cleanup
	time.Sleep(150 * time.Millisecond)
	store.Cleanup()

	// Should be cleaned up
	if store.Size() > 0 {
		t.Error("entries should be cleaned up after expiry")
	}
}

func TestNoOpReplayStore(t *testing.T) {
	store := NewNoOpReplayStore()

	// Should never detect replay
	if store.Seen("jkt", "jti", "GET", "url", 123) {
		t.Error("NoOpReplayStore should never detect replay")
	}

	if store.Seen("jkt", "jti", "GET", "url", 123) {
		t.Error("NoOpReplayStore should never detect replay")
	}

	store.Cleanup() // Should not panic
}

func TestRSAJWKConversion(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Convert to JWK
	jwk, err := PublicKeyToJWK(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to convert RSA key to JWK: %v", err)
	}

	// Verify JWK fields
	if jwk.Kty != "RSA" {
		t.Errorf("expected kty 'RSA', got %s", jwk.Kty)
	}

	if jwk.N == "" || jwk.E == "" {
		t.Error("N and E should not be empty for RSA keys")
	}

	// Convert back to public key
	convertedKey, err := jwkToPublicKey(jwk)
	if err != nil {
		t.Fatalf("failed to convert RSA JWK back to public key: %v", err)
	}

	rsaKey, ok := convertedKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("converted key should be RSA public key")
	}

	// Should be the same key
	if privateKey.PublicKey.N.Cmp(rsaKey.N) != 0 || privateKey.PublicKey.E != rsaKey.E {
		t.Error("converted RSA key should match original")
	}
}

func TestComputeJWKThumbprintEdgeCases(t *testing.T) {
	// Test unsupported key type
	jwk := &JWK{
		Kty: "OKP", // Unsupported type
		X:   "test-x",
	}

	thumbprint := computeJWKThumbprint(jwk)
	if thumbprint == "" {
		t.Error("thumbprint should not be empty even for unsupported types")
	}

	// Test empty JWK
	emptyJWK := &JWK{}
	emptyThumbprint := computeJWKThumbprint(emptyJWK)
	if emptyThumbprint == "" {
		t.Error("empty JWK should still produce a thumbprint")
	}

	// Different unsupported types should produce different thumbprints
	jwk2 := &JWK{
		Kty: "UNKNOWN",
		X:   "different-x",
	}
	thumbprint2 := computeJWKThumbprint(jwk2)
	if thumbprint == thumbprint2 {
		t.Error("different JWKs should produce different thumbprints")
	}
}

func TestCanonicalURLEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		u        *url.URL
		host     string
		proto    string
		expected string
	}{
		{
			name:     "missing scheme with https proto",
			u:        &url.URL{Path: "/test", RawQuery: "q=1"},
			host:     "example.com",
			proto:    "https",
			expected: "https://example.com/test?q=1",
		},
		{
			name:     "missing scheme with http proto",
			u:        &url.URL{Path: "/test"},
			host:     "example.com",
			proto:    "http",
			expected: "http://example.com/test",
		},
		{
			name:     "missing host",
			u:        &url.URL{Scheme: "https", Path: "/test"},
			host:     "fallback.com",
			proto:    "",
			expected: "https://fallback.com/test",
		},
		{
			name:     "complete URL",
			u:        &url.URL{Scheme: "https", Host: "api.example.com", Path: "/v1/test", RawQuery: "param=value"},
			host:     "",
			proto:    "",
			expected: "https://api.example.com/v1/test?param=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canonicalURL(tt.u, tt.host, tt.proto)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestEqualURLsEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		url1     string
		url2     string
		expected bool
	}{
		{
			name:     "invalid url1",
			url1:     "://invalid",
			url2:     "https://example.com/test",
			expected: false,
		},
		{
			name:     "invalid url2",
			url1:     "https://example.com/test",
			url2:     "://invalid",
			expected: false,
		},
		{
			name:     "case insensitive scheme",
			url1:     "HTTPS://example.com/test",
			url2:     "https://example.com/test",
			expected: true,
		},
		{
			name:     "case insensitive host",
			url1:     "https://EXAMPLE.COM/test",
			url2:     "https://example.com/test",
			expected: true,
		},
		{
			name:     "different query params",
			url1:     "https://example.com/test?a=1",
			url2:     "https://example.com/test?b=2",
			expected: false,
		},
		{
			name:     "same with fragment differences (ignored)",
			url1:     "https://example.com/test#frag1",
			url2:     "https://example.com/test#frag2",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := equalURLs(tt.url1, tt.url2)
			if result != tt.expected {
				t.Errorf("expected %t, got %t", tt.expected, result)
			}
		})
	}
}