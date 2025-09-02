package jwt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// TokenSigner defines the interface for JWT signing
type TokenSigner interface {
	// Sign creates a JWT with the given claims
	Sign(claims map[string]interface{}) (string, error)
	
	// JWKS returns the public keys for JWT verification
	JWKS() jwk.Set
	
	// Algorithm returns the signing algorithm
	Algorithm() string
}

// TokenVerifier defines the interface for JWT verification
type TokenVerifier interface {
	// Verify verifies a JWT and returns the claims
	Verify(token string, expectedAudience string) (*Claims, error)
	
	// VerifyWithKey verifies a JWT using a specific key
	VerifyWithKey(token string, expectedAudience string, publicKey interface{}) (*Claims, error)
}

// Claims represents the claims in a zkDPoP JWT
type Claims struct {
	Issuer    string                 `json:"iss"`
	Subject   string                 `json:"sub"`
	Audience  string                 `json:"aud"`
	IssuedAt  int64                  `json:"iat"`
	ExpiresAt int64                  `json:"exp"`
	Cnf       *ConfirmationClaims    `json:"cnf,omitempty"` // Confirmation claims (cnf.jkt)
	ZK        *ZKClaims              `json:"zk,omitempty"`  // ZK-specific claims
	Extra     map[string]interface{} `json:"-"`             // Additional claims
	jwt.RegisteredClaims
}

// ConfirmationClaims represents the "cnf" claim for proof-of-possession
type ConfirmationClaims struct {
	JKT string `json:"jkt"` // JWK thumbprint (SHA-256, base64url)
}

// ZKClaims represents ZK-specific claims in the JWT
type ZKClaims struct {
	Scheme    string `json:"scheme"`   // "schnorr-id"
	Group     string `json:"grp"`      // "secp256k1" or "ristretto255"
	THash     string `json:"t_hash"`   // Base64 hash of commitment T
	Challenge string `json:"c"`        // Base64 challenge scalar
	Timeslice string `json:"ts"`       // RFC3339 timeslice
}

// ES256Signer implements JWT signing using ECDSA P-256
type ES256Signer struct {
	privateKey *ecdsa.PrivateKey
	keyID      string
	issuer     string
	jwks       jwk.Set
}

// NewES256Signer creates a new ES256 JWT signer
func NewES256Signer(privateKey *ecdsa.PrivateKey, keyID, issuer string) (*ES256Signer, error) {
	// Create JWK set with the public key
	publicJWK, err := jwk.FromRaw(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from public key: %w", err)
	}

	if err := publicJWK.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	if err := publicJWK.Set(jwk.AlgorithmKey, "ES256"); err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}

	if err := publicJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("failed to set key usage: %w", err)
	}

	jwks := jwk.NewSet()
	jwks.AddKey(publicJWK)

	return &ES256Signer{
		privateKey: privateKey,
		keyID:      keyID,
		issuer:     issuer,
		jwks:       jwks,
	}, nil
}

// Sign creates a JWT with the given claims
func (s *ES256Signer) Sign(claims map[string]interface{}) (string, error) {
	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))

	// Set key ID in header
	token.Header["kid"] = s.keyID

	// Sign the token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

// JWKS returns the public keys for JWT verification
func (s *ES256Signer) JWKS() jwk.Set {
	return s.jwks
}

// Algorithm returns the signing algorithm
func (s *ES256Signer) Algorithm() string {
	return "ES256"
}

// JWTVerifier implements JWT verification
type JWTVerifier struct {
	issuerJWKS jwk.Set
}

// NewJWTVerifier creates a new JWT verifier
func NewJWTVerifier(issuerJWKS jwk.Set) *JWTVerifier {
	return &JWTVerifier{
		issuerJWKS: issuerJWKS,
	}
}

// Verify verifies a JWT and returns the claims
func (v *JWTVerifier) Verify(tokenString string, expectedAudience string) (*Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check algorithm
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing key ID")
		}

		// Find key in JWKS
		key, ok := v.issuerJWKS.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key not found: %s", kid)
		}

		// Convert to public key
		var publicKey interface{}
		if err := key.Raw(&publicKey); err != nil {
			return nil, fmt.Errorf("failed to extract public key: %w", err)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT")
	}

	// Extract claims
	claimsMap := token.Claims.(jwt.MapClaims)
	
	// Verify audience
	if aud, ok := claimsMap["aud"].(string); ok {
		if aud != expectedAudience {
			return nil, fmt.Errorf("invalid audience: expected %s, got %s", expectedAudience, aud)
		}
	} else {
		return nil, fmt.Errorf("missing audience claim")
	}

	// Parse claims into structured format
	claims, err := parseClaimsMap(claimsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims, nil
}

// VerifyWithKey verifies a JWT using a specific key
func (v *JWTVerifier) VerifyWithKey(tokenString string, expectedAudience string, publicKey interface{}) (*Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check algorithm
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT")
	}

	// Extract and verify claims
	claimsMap := token.Claims.(jwt.MapClaims)
	
	// Verify audience
	if aud, ok := claimsMap["aud"].(string); ok {
		if aud != expectedAudience {
			return nil, fmt.Errorf("invalid audience: expected %s, got %s", expectedAudience, aud)
		}
	} else {
		return nil, fmt.Errorf("missing audience claim")
	}

	// Parse claims
	claims, err := parseClaimsMap(claimsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims, nil
}

// parseClaimsMap parses JWT claims map into structured Claims
func parseClaimsMap(claimsMap jwt.MapClaims) (*Claims, error) {
	claims := &Claims{
		Extra: make(map[string]interface{}),
	}

	// Parse standard claims
	if iss, ok := claimsMap["iss"].(string); ok {
		claims.Issuer = iss
	}

	if sub, ok := claimsMap["sub"].(string); ok {
		claims.Subject = sub
	}

	if aud, ok := claimsMap["aud"].(string); ok {
		claims.Audience = aud
	}

	if iat, ok := claimsMap["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}

	if exp, ok := claimsMap["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}

	// Parse confirmation claims (cnf.jkt)
	if cnfRaw, ok := claimsMap["cnf"].(map[string]interface{}); ok {
		claims.Cnf = &ConfirmationClaims{}
		if jkt, ok := cnfRaw["jkt"].(string); ok {
			claims.Cnf.JKT = jkt
		}
	}

	// Parse ZK claims
	if zkRaw, ok := claimsMap["zk"].(map[string]interface{}); ok {
		claims.ZK = &ZKClaims{}
		if scheme, ok := zkRaw["scheme"].(string); ok {
			claims.ZK.Scheme = scheme
		}
		if grp, ok := zkRaw["grp"].(string); ok {
			claims.ZK.Group = grp
		}
		if tHash, ok := zkRaw["t_hash"].(string); ok {
			claims.ZK.THash = tHash
		}
		if c, ok := zkRaw["c"].(string); ok {
			claims.ZK.Challenge = c
		}
		if ts, ok := zkRaw["ts"].(string); ok {
			claims.ZK.Timeslice = ts
		}
	}

	// Store any additional claims
	for k, v := range claimsMap {
		if k != "iss" && k != "sub" && k != "aud" && k != "iat" && k != "exp" && k != "cnf" && k != "zk" {
			claims.Extra[k] = v
		}
	}

	return claims, nil
}

// MintZKDPoPToken creates a zkDPoP JWT with the specified parameters
func MintZKDPoPToken(
	signer TokenSigner,
	issuer, subject, audience string,
	jkt string, // DPoP JWK thumbprint
	T, c []byte, // ZK commitment and challenge
	timeslice time.Time,
	groupName string,
	ttl time.Duration,
) (string, error) {
	now := time.Now()

	// Compute hash of commitment T
	tHash := sha256.Sum256(T)

	claims := map[string]interface{}{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"cnf": map[string]interface{}{
			"jkt": jkt, // Bind to DPoP JWK thumbprint
		},
		"zk": map[string]interface{}{
			"scheme":  "schnorr-id",
			"grp":     groupName,
			"t_hash":  base64.StdEncoding.EncodeToString(tHash[:]),
			"c":       base64.StdEncoding.EncodeToString(c),
			"ts":      timeslice.Format(time.RFC3339),
		},
	}

	return signer.Sign(claims)
}

// GeneratePairwiseSubject generates a pairwise subject identifier
func GeneratePairwiseSubject(pk []byte, audience string) string {
	// Create deterministic but opaque subject ID
	h := sha256.New()
	h.Write([]byte("zkdpop/1/sub"))
	h.Write(pk)
	h.Write([]byte(audience))
	
	hash := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash)
}