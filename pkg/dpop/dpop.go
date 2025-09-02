package dpop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DPoPClaims represents the claims in a DPoP proof JWT
type DPoPClaims struct {
	HTM string `json:"htm"` // HTTP method
	HTU string `json:"htu"` // HTTP URI
	IAT int64  `json:"iat"` // Issued at
	JTI string `json:"jti"` // JWT ID (for replay protection)
	jwt.RegisteredClaims
}

// DPoPResult contains the result of DPoP verification
type DPoPResult struct {
	JKT    string    // JWK thumbprint (SHA-256)
	Claims DPoPClaims // Verified claims
	JWK    JWK       // The JWK used for verification
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key type
	Alg string `json:"alg"` // Algorithm
	Use string `json:"use"` // Key use
	X   string `json:"x"`   // X coordinate (for EC keys)
	Y   string `json:"y"`   // Y coordinate (for EC keys)  
	Crv string `json:"crv"` // Curve (for EC keys)
	N   string `json:"n"`   // Modulus (for RSA keys)
	E   string `json:"e"`   // Exponent (for RSA keys)
}

// ReplayStore defines the interface for DPoP replay detection
type ReplayStore interface {
	// Seen checks if a DPoP proof has been seen before and marks it as seen
	// Returns true if the proof was already seen (replay attack)
	Seen(jkt, jti, htm, htu string, minute int64) bool
	
	// Cleanup removes expired entries from the store
	Cleanup()
}

var (
	// ErrInvalidDPoP indicates the DPoP proof is invalid
	ErrInvalidDPoP = fmt.Errorf("invalid DPoP proof")
	
	// ErrBoundMismatch indicates the DPoP proof doesn't match the request
	ErrBoundMismatch = fmt.Errorf("DPoP proof binding mismatch")
	
	// ErrReplay indicates a DPoP proof replay attack
	ErrReplay = fmt.Errorf("DPoP proof replay detected")
	
	// ErrExpired indicates the DPoP proof has expired
	ErrExpired = fmt.Errorf("DPoP proof expired")
	
	// ErrUnsupportedAlg indicates an unsupported algorithm
	ErrUnsupportedAlg = fmt.Errorf("unsupported DPoP algorithm")
)

// VerifyDPoP verifies a DPoP proof from an HTTP request
func VerifyDPoP(r *http.Request, replayStore ReplayStore) (*DPoPResult, error) {
	// Get DPoP header
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return nil, fmt.Errorf("%w: missing DPoP header", ErrInvalidDPoP)
	}

	// Parse and verify the DPoP JWT
	token, jwk, claims, err := parseAndVerifyDPoP(dpopHeader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDPoP, err)
	}
	_ = token // We might need this for additional validations

	// Verify method binding
	if claims.HTM != r.Method {
		return nil, fmt.Errorf("%w: method mismatch, expected %s, got %s", ErrBoundMismatch, r.Method, claims.HTM)
	}

	// Verify URL binding
	requestURL := canonicalURL(r.URL, r.Host, r.Header.Get("X-Forwarded-Proto"))
	if !equalURLs(claims.HTU, requestURL) {
		return nil, fmt.Errorf("%w: URL mismatch, expected %s, got %s", ErrBoundMismatch, requestURL, claims.HTU)
	}

	// Check timestamp (allow 60 second skew)
	now := time.Now().Unix()
	clockSkew := int64(60)
	if claims.IAT > now+clockSkew || claims.IAT < now-clockSkew {
		return nil, fmt.Errorf("%w: timestamp outside acceptable range", ErrExpired)
	}

	// Check for replay
	jkt := computeJWKThumbprint(jwk)
	minute := claims.IAT / 60 // Group by minute for replay detection
	if replayStore.Seen(jkt, claims.JTI, claims.HTM, claims.HTU, minute) {
		return nil, ErrReplay
	}

	return &DPoPResult{
		JKT:    jkt,
		Claims: *claims,
		JWK:    *jwk,
	}, nil
}

// parseAndVerifyDPoP parses and verifies a DPoP JWT
func parseAndVerifyDPoP(dpopToken string) (*jwt.Token, *JWK, *DPoPClaims, error) {
	// Parse JWT header to get JWK
	token, err := jwt.Parse(dpopToken, func(token *jwt.Token) (interface{}, error) {
		// Get JWK from header
		jwkRaw, ok := token.Header["jwk"]
		if !ok {
			return nil, fmt.Errorf("missing jwk in header")
		}

		jwkMap, ok := jwkRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid jwk format")
		}

		jwkBytes, err := json.Marshal(jwkMap)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal jwk: %w", err)
		}

		var jwk JWK
		if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
			return nil, fmt.Errorf("failed to unmarshal jwk: %w", err)
		}

		// Convert JWK to public key for verification
		publicKey, err := jwkToPublicKey(&jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to convert jwk to public key: %w", err)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, nil, nil, err
	}

	if !token.Valid {
		return nil, nil, nil, fmt.Errorf("invalid token")
	}

	// Extract JWK from header
	jwkRaw := token.Header["jwk"]
	jwkMap := jwkRaw.(map[string]interface{})
	jwkBytes, _ := json.Marshal(jwkMap)
	var jwk JWK
	json.Unmarshal(jwkBytes, &jwk)

	// Extract claims
	claimsMap := token.Claims.(jwt.MapClaims)
	claims := &DPoPClaims{}

	if htm, ok := claimsMap["htm"].(string); ok {
		claims.HTM = htm
	} else {
		return nil, nil, nil, fmt.Errorf("missing htm claim")
	}

	if htu, ok := claimsMap["htu"].(string); ok {
		claims.HTU = htu
	} else {
		return nil, nil, nil, fmt.Errorf("missing htu claim")
	}

	if iat, ok := claimsMap["iat"].(float64); ok {
		claims.IAT = int64(iat)
	} else {
		return nil, nil, nil, fmt.Errorf("missing iat claim")
	}

	if jti, ok := claimsMap["jti"].(string); ok {
		claims.JTI = jti
	} else {
		return nil, nil, nil, fmt.Errorf("missing jti claim")
	}

	return token, &jwk, claims, nil
}

// computeJWKThumbprint computes the SHA-256 thumbprint of a JWK per RFC 7638
func computeJWKThumbprint(jwk *JWK) string {
	// Create canonical JWK representation
	canonical := make(map[string]interface{})

	switch jwk.Kty {
	case "EC":
		canonical["crv"] = jwk.Crv
		canonical["kty"] = jwk.Kty
		canonical["x"] = jwk.X
		canonical["y"] = jwk.Y
	case "RSA":
		canonical["e"] = jwk.E
		canonical["kty"] = jwk.Kty
		canonical["n"] = jwk.N
	default:
		// Fallback: include all non-empty fields
		if jwk.Kty != "" {
			canonical["kty"] = jwk.Kty
		}
		if jwk.Crv != "" {
			canonical["crv"] = jwk.Crv
		}
		if jwk.X != "" {
			canonical["x"] = jwk.X
		}
		if jwk.Y != "" {
			canonical["y"] = jwk.Y
		}
		if jwk.N != "" {
			canonical["n"] = jwk.N
		}
		if jwk.E != "" {
			canonical["e"] = jwk.E
		}
	}

	// Marshal to JSON (keys are sorted by encoding/json)
	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		// This should never happen with well-formed data
		return ""
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(canonicalJSON)

	// Encode as base64url
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// canonicalURL creates a canonical representation of the URL for DPoP verification
func canonicalURL(u *url.URL, host, proto string) string {
	scheme := u.Scheme
	if scheme == "" {
		if proto == "https" {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	hostname := u.Host
	if hostname == "" {
		hostname = host
	}

	return fmt.Sprintf("%s://%s%s", scheme, hostname, u.RequestURI())
}

// equalURLs compares two URLs for DPoP verification
func equalURLs(url1, url2 string) bool {
	// Parse both URLs
	u1, err1 := url.Parse(url1)
	u2, err2 := url.Parse(url2)

	if err1 != nil || err2 != nil {
		return false
	}

	// Compare scheme, host, and path (ignore fragments)
	return strings.EqualFold(u1.Scheme, u2.Scheme) &&
		strings.EqualFold(u1.Host, u2.Host) &&
		u1.Path == u2.Path &&
		u1.RawQuery == u2.RawQuery
}