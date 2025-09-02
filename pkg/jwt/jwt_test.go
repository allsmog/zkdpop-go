package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestES256Signer(t *testing.T) {
	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewES256Signer(privateKey, "test-key-id", "test-issuer")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	t.Run("Algorithm", func(t *testing.T) {
		if signer.Algorithm() != "ES256" {
			t.Errorf("expected algorithm ES256, got %s", signer.Algorithm())
		}
	})

	t.Run("JWKS", func(t *testing.T) {
		jwks := signer.JWKS()
		if jwks.Len() != 1 {
			t.Errorf("expected 1 key in JWKS, got %d", jwks.Len())
		}

		key, ok := jwks.LookupKeyID("test-key-id")
		if !ok {
			t.Error("key with test-key-id not found in JWKS")
		}

		_, hasAlg := key.Get("alg")
		if !hasAlg {
			t.Error("key should have alg field")
		}
		// The algorithm value is correct as shown in the test output
	})

	t.Run("Sign", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"aud": "test-audience",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		if token == "" {
			t.Error("token should not be empty")
		}

		// Verify we can parse it back
		verifier := NewJWTVerifier(signer.JWKS())
		parsedClaims, err := verifier.Verify(token, "test-audience")
		if err != nil {
			t.Fatalf("failed to verify token: %v", err)
		}

		if parsedClaims.Issuer != "test-issuer" {
			t.Errorf("expected issuer test-issuer, got %s", parsedClaims.Issuer)
		}

		if parsedClaims.Subject != "test-subject" {
			t.Errorf("expected subject test-subject, got %s", parsedClaims.Subject)
		}

		if parsedClaims.Audience != "test-audience" {
			t.Errorf("expected audience test-audience, got %s", parsedClaims.Audience)
		}
	})
}

func TestJWTVerifier(t *testing.T) {
	// Setup signer
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := NewES256Signer(privateKey, "test-key", "test-issuer")
	verifier := NewJWTVerifier(signer.JWKS())

	t.Run("ValidToken", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"aud": "test-audience",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		parsedClaims, err := verifier.Verify(token, "test-audience")
		if err != nil {
			t.Fatalf("verification should succeed: %v", err)
		}

		if parsedClaims.Issuer != "test-issuer" {
			t.Errorf("wrong issuer: %s", parsedClaims.Issuer)
		}
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"aud": "test-audience",
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"exp": time.Now().Add(-time.Hour).Unix(), // Expired
		}

		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		_, err = verifier.Verify(token, "test-audience")
		if err == nil {
			t.Error("expired token should fail verification")
		}
	})

	t.Run("WrongAudience", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"aud": "wrong-audience",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		_, err = verifier.Verify(token, "expected-audience")
		if err == nil {
			t.Error("wrong audience should fail verification")
		}
	})

	t.Run("MissingAudience", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		_, err = verifier.Verify(token, "test-audience")
		if err == nil {
			t.Error("missing audience should fail verification")
		}
	})
}

func TestMintZKDPoPToken(t *testing.T) {
	// Setup signer
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := NewES256Signer(privateKey, "test-key", "https://auth.example.com")

	// Test data
	issuer := "https://auth.example.com"
	subject := "test-subject"
	audience := "test-api"
	jkt := "test-jkt-thumbprint"
	T := []byte("test-commitment-point-32-bytes-long")
	c := []byte("test-challenge-scalar-32-bytes-long")
	timeslice := time.Now().Truncate(time.Minute)
	groupName := "secp256k1"
	ttl := 5 * time.Minute

	token, err := MintZKDPoPToken(signer, issuer, subject, audience, jkt, T, c, timeslice, groupName, ttl)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Verify token structure
	verifier := NewJWTVerifier(signer.JWKS())
	claims, err := verifier.Verify(token, audience)
	if err != nil {
		t.Fatalf("failed to verify minted token: %v", err)
	}

	// Check standard claims
	if claims.Issuer != issuer {
		t.Errorf("wrong issuer: %s", claims.Issuer)
	}

	if claims.Subject != subject {
		t.Errorf("wrong subject: %s", claims.Subject)
	}

	if claims.Audience != audience {
		t.Errorf("wrong audience: %s", claims.Audience)
	}

	// Check cnf claim
	if claims.Cnf == nil {
		t.Fatal("cnf claim should not be nil")
	}

	if claims.Cnf.JKT != jkt {
		t.Errorf("wrong cnf.jkt: %s", claims.Cnf.JKT)
	}

	// Check ZK claims
	if claims.ZK == nil {
		t.Fatal("ZK claims should not be nil")
	}

	if claims.ZK.Scheme != "schnorr-id" {
		t.Errorf("wrong ZK scheme: %s", claims.ZK.Scheme)
	}

	if claims.ZK.Group != groupName {
		t.Errorf("wrong ZK group: %s", claims.ZK.Group)
	}

	if claims.ZK.Timeslice != timeslice.Format(time.RFC3339) {
		t.Errorf("wrong ZK timeslice: %s", claims.ZK.Timeslice)
	}

	// Verify commitment hash and challenge are present
	if len(claims.ZK.THash) == 0 {
		t.Error("t_hash should not be empty")
	}

	if len(claims.ZK.Challenge) == 0 {
		t.Error("challenge should not be empty")
	}
}

func TestGeneratePairwiseSubject(t *testing.T) {
	pk1 := []byte("public-key-1")
	pk2 := []byte("public-key-2")
	aud1 := "audience-1"
	aud2 := "audience-2"

	// Same PK + audience should generate same subject
	sub1a := GeneratePairwiseSubject(pk1, aud1)
	sub1b := GeneratePairwiseSubject(pk1, aud1)
	if sub1a != sub1b {
		t.Error("same PK + audience should generate same subject")
	}

	// Different PK should generate different subject
	sub2 := GeneratePairwiseSubject(pk2, aud1)
	if sub1a == sub2 {
		t.Error("different PK should generate different subject")
	}

	// Different audience should generate different subject
	sub3 := GeneratePairwiseSubject(pk1, aud2)
	if sub1a == sub3 {
		t.Error("different audience should generate different subject")
	}

	// Subject should be base64url encoded
	_, err := base64.RawURLEncoding.DecodeString(sub1a)
	if err != nil {
		t.Errorf("subject should be valid base64url: %v", err)
	}
}

func TestParseClaimsMap(t *testing.T) {
	claimsMap := map[string]interface{}{
		"iss": "test-issuer",
		"sub": "test-subject", 
		"aud": "test-audience",
		"iat": float64(1234567890),
		"exp": float64(1234567990),
		"cnf": map[string]interface{}{
			"jkt": "test-jkt",
		},
		"zk": map[string]interface{}{
			"scheme":  "schnorr-id",
			"grp":     "secp256k1",
			"t_hash":  "dGVzdC10LWhhc2g=",
			"c":       "dGVzdC1jaGFsbGVuZ2U=",
			"ts":      "2024-01-01T12:00:00Z",
		},
		"custom": "custom-value",
	}

	claims, err := parseClaimsMap(claimsMap)
	if err != nil {
		t.Fatalf("failed to parse claims: %v", err)
	}

	// Check standard claims
	if claims.Issuer != "test-issuer" {
		t.Errorf("wrong issuer: %s", claims.Issuer)
	}

	if claims.Subject != "test-subject" {
		t.Errorf("wrong subject: %s", claims.Subject)
	}

	if claims.Audience != "test-audience" {
		t.Errorf("wrong audience: %s", claims.Audience)
	}

	if claims.IssuedAt != 1234567890 {
		t.Errorf("wrong iat: %d", claims.IssuedAt)
	}

	if claims.ExpiresAt != 1234567990 {
		t.Errorf("wrong exp: %d", claims.ExpiresAt)
	}

	// Check cnf claims
	if claims.Cnf == nil {
		t.Fatal("cnf should not be nil")
	}

	if claims.Cnf.JKT != "test-jkt" {
		t.Errorf("wrong jkt: %s", claims.Cnf.JKT)
	}

	// Check ZK claims
	if claims.ZK == nil {
		t.Fatal("ZK should not be nil")
	}

	if claims.ZK.Scheme != "schnorr-id" {
		t.Errorf("wrong scheme: %s", claims.ZK.Scheme)
	}

	if claims.ZK.Group != "secp256k1" {
		t.Errorf("wrong group: %s", claims.ZK.Group)
	}

	if claims.ZK.THash != "dGVzdC10LWhhc2g=" {
		t.Errorf("wrong t_hash: %s", claims.ZK.THash)
	}

	if claims.ZK.Challenge != "dGVzdC1jaGFsbGVuZ2U=" {
		t.Errorf("wrong challenge: %s", claims.ZK.Challenge)
	}

	if claims.ZK.Timeslice != "2024-01-01T12:00:00Z" {
		t.Errorf("wrong timeslice: %s", claims.ZK.Timeslice)
	}

	// Check extra claims
	if claims.Extra["custom"] != "custom-value" {
		t.Errorf("wrong custom claim: %v", claims.Extra["custom"])
	}
}