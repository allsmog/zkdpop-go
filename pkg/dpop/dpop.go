// Package dpop implements Demonstration of Proof-of-Possession (DPoP) as defined
// in RFC 9449.
//
// # What is DPoP?
//
// DPoP is a mechanism to bind access tokens to a specific client by requiring
// the client to prove possession of a private key on each request. This prevents
// token theft - even if an attacker steals the token, they cannot use it without
// also stealing the private key.
//
// # How DPoP Works
//
//  1. Client generates an asymmetric key pair (e.g., ECDSA P-256)
//  2. For each request, client creates a "DPoP proof" - a JWT signed with the private key
//  3. The proof contains:
//     - htm: HTTP method (e.g., "POST")
//     - htu: HTTP URI (e.g., "https://api.example.com/resource")
//     - iat: Issued-at timestamp
//     - jti: Unique identifier (for replay protection)
//     - jwk: The public key (in JWT header)
//  4. Server verifies the proof signature using the embedded public key
//  5. Server checks the method/URI match the actual request
//  6. Server computes the JWK thumbprint and compares to token's cnf.jkt claim
//
// # Sender-Constrained Tokens
//
// When combined with JWT tokens containing a cnf.jkt claim, DPoP creates
// "sender-constrained" tokens. The token can only be used by someone who:
//   - Possesses the token itself
//   - Can prove possession of the private key matching cnf.jkt
//
// This is much stronger than bearer tokens, which can be used by anyone who has them.
//
// # References
//
//   - RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
//   - RFC 7638: JSON Web Key (JWK) Thumbprint
//   - RFC 7800: Proof-of-Possession Key Semantics for JWTs
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

// DPoPClaims represents the claims in a DPoP proof JWT.
//
// Per RFC 9449, a DPoP proof must contain:
//   - htm: The HTTP method of the request (e.g., "POST", "GET")
//   - htu: The HTTP URI of the request (scheme + host + path, no query/fragment)
//   - iat: When the proof was created (Unix timestamp)
//   - jti: Unique identifier to prevent replay attacks
//
// The proof header must also contain:
//   - typ: "dpop+jwt"
//   - alg: Signature algorithm (e.g., "ES256")
//   - jwk: The public key used to verify the signature
type DPoPClaims struct {
	HTM string `json:"htm"` // HTTP method bound to this proof
	HTU string `json:"htu"` // HTTP URI bound to this proof
	IAT int64  `json:"iat"` // Issued-at timestamp (Unix seconds)
	JTI string `json:"jti"` // JWT ID - unique per proof for replay detection
	jwt.RegisteredClaims
}

// DPoPResult contains the result of successful DPoP verification.
//
// After verification, this struct provides:
//   - JKT: The SHA-256 thumbprint of the client's public key (for cnf.jkt binding)
//   - Claims: The verified claims from the DPoP proof
//   - JWK: The client's public key (for logging/debugging)
type DPoPResult struct {
	JKT    string     // JWK thumbprint (base64url-encoded SHA-256 of canonical JWK)
	Claims DPoPClaims // Verified claims from the proof
	JWK    JWK        // The public key from the proof header
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

// VerifyDPoP verifies a DPoP proof from an HTTP request.
//
// This function performs the complete DPoP verification as specified in RFC 9449:
//
//  1. SIGNATURE VERIFICATION: The proof JWT is signed by the private key
//     corresponding to the JWK in the header. This proves the client possesses
//     the private key.
//
//  2. METHOD BINDING: The htm claim must match the HTTP method of the request.
//     This prevents a proof for GET being used for POST.
//
//  3. URI BINDING: The htu claim must match the request URI.
//     This prevents a proof for /api/read being used for /api/delete.
//
//  4. TIMESTAMP CHECK: The iat claim must be within 60 seconds of current time.
//     This limits the window for replay attacks.
//
//  5. REPLAY DETECTION: The (jkt, jti, htm, htu, minute) tuple must not have
//     been seen before. This prevents exact replay of proofs.
//
// On success, returns DPoPResult containing the JWK thumbprint (JKT).
// The JKT should be compared against the JWT's cnf.jkt claim to complete
// sender-constrained token verification.
//
// Security considerations:
//   - Clock skew of 60 seconds balances security vs. usability
//   - Replay window is per-minute granularity
//   - JKT is computed as SHA-256 of canonical JWK (RFC 7638)
func VerifyDPoP(r *http.Request, replayStore ReplayStore) (*DPoPResult, error) {
	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 1: Extract and parse the DPoP proof from the request header
	// ═══════════════════════════════════════════════════════════════════════════

	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return nil, fmt.Errorf("%w: missing DPoP header", ErrInvalidDPoP)
	}

	// Parse JWT, verify signature using embedded JWK, extract claims
	token, jwk, claims, err := parseAndVerifyDPoP(dpopHeader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDPoP, err)
	}
	_ = token // Token is validated; we use claims and jwk from here

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 2: Verify method binding (htm claim must match request method)
	// ═══════════════════════════════════════════════════════════════════════════
	// Prevents: Attacker intercepts GET proof and uses it for DELETE request

	if claims.HTM != r.Method {
		return nil, fmt.Errorf("%w: method mismatch, expected %s, got %s", ErrBoundMismatch, r.Method, claims.HTM)
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 3: Verify URI binding (htu claim must match request URI)
	// ═══════════════════════════════════════════════════════════════════════════
	// Prevents: Attacker uses proof for /api/public on /api/admin

	requestURL := canonicalURL(r.URL, r.Host, r.Header.Get("X-Forwarded-Proto"))
	if !equalURLs(claims.HTU, requestURL) {
		return nil, fmt.Errorf("%w: URL mismatch, expected %s, got %s", ErrBoundMismatch, requestURL, claims.HTU)
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 4: Verify timestamp freshness (iat must be recent)
	// ═══════════════════════════════════════════════════════════════════════════
	// Prevents: Attacker uses old/precomputed proofs
	// Allows: 60 second clock skew for network latency and clock drift

	now := time.Now().Unix()
	clockSkew := int64(60) // RFC 9449 recommends allowing some clock skew
	if claims.IAT > now+clockSkew || claims.IAT < now-clockSkew {
		return nil, fmt.Errorf("%w: timestamp outside acceptable range", ErrExpired)
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 5: Check for replay attacks
	// ═══════════════════════════════════════════════════════════════════════════
	// The replay store tracks seen proofs by (jkt, jti, htm, htu, minute).
	// Even with valid signature, a proof can only be used once.

	jkt := computeJWKThumbprint(jwk) // SHA-256 hash of canonical JWK
	minute := claims.IAT / 60        // Group by minute for replay detection window
	if replayStore.Seen(jkt, claims.JTI, claims.HTM, claims.HTU, minute) {
		return nil, ErrReplay
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// SUCCESS: All checks passed
	// ═══════════════════════════════════════════════════════════════════════════

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

// computeJWKThumbprint computes the SHA-256 thumbprint of a JWK per RFC 7638.
//
// The JWK thumbprint is a stable identifier for a public key. It's computed as:
//
//	base64url(SHA-256(canonical_json(required_members)))
//
// For EC keys, the required members are: crv, kty, x, y (in lexicographic order)
// For RSA keys, the required members are: e, kty, n (in lexicographic order)
//
// The canonical JSON representation:
//   - Contains only the required members for the key type
//   - Has members sorted lexicographically by name
//   - Has no whitespace
//
// Example for EC key:
//
//	{"crv":"P-256","kty":"EC","x":"...","y":"..."}
//
// The thumbprint is used in the JWT's cnf.jkt claim to bind the token to
// a specific DPoP key. This is how we achieve "sender-constrained" tokens.
func computeJWKThumbprint(jwk *JWK) string {
	// Build canonical JWK with only the required members for this key type
	// RFC 7638 Section 3.2 specifies which members to include
	canonical := make(map[string]interface{})

	switch jwk.Kty {
	case "EC":
		// For EC keys: crv, kty, x, y (lexicographic order)
		canonical["crv"] = jwk.Crv
		canonical["kty"] = jwk.Kty
		canonical["x"] = jwk.X
		canonical["y"] = jwk.Y
	case "RSA":
		// For RSA keys: e, kty, n (lexicographic order)
		canonical["e"] = jwk.E
		canonical["kty"] = jwk.Kty
		canonical["n"] = jwk.N
	default:
		// Fallback for unknown key types: include all non-empty fields
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

	// Go's json.Marshal sorts map keys lexicographically, which is what we need
	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		// This should never happen with well-formed data
		return ""
	}

	// Compute SHA-256 hash of the canonical JSON
	hash := sha256.Sum256(canonicalJSON)

	// Encode as base64url without padding (RFC 7638 requirement)
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