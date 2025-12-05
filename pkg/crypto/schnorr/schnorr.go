// Package schnorr implements the Schnorr identification protocol for zero-knowledge
// proof of possession of a private key.
//
// # Schnorr Identification Protocol Overview
//
// The Schnorr protocol allows a Prover to convince a Verifier that they know a
// secret key x corresponding to a public key PK = x*G, without revealing x.
//
// The protocol works as follows:
//
//  1. COMMITMENT (Prover → Verifier):
//     - Prover generates random nonce r
//     - Prover computes commitment T = r*G
//     - Prover sends T to Verifier
//
//  2. CHALLENGE (Verifier → Prover):
//     - Verifier generates/derives challenge c
//     - Verifier sends c to Prover
//
//  3. RESPONSE (Prover → Verifier):
//     - Prover computes response s = r + c*x (mod q)
//     - Prover sends s to Verifier
//
//  4. VERIFICATION:
//     - Verifier checks: s*G == T + c*PK
//     - If equal, proof is valid (Prover knows x)
//
// # Why This Works (Mathematical Intuition)
//
// The verification equation s*G == T + c*PK holds because:
//
//	s*G = (r + c*x)*G           // substituting s = r + c*x
//	    = r*G + c*x*G           // distributive property
//	    = T + c*PK              // since T = r*G and PK = x*G
//
// # Zero-Knowledge Property
//
// The protocol is zero-knowledge because:
//   - The commitment T is a random point (reveals nothing about x)
//   - The response s = r + c*x is uniformly random (r masks x)
//   - A simulator can produce valid-looking transcripts without knowing x
//
// # Security Properties
//
//   - COMPLETENESS: Honest prover always convinces honest verifier
//   - SOUNDNESS: Cheating prover succeeds with negligible probability
//   - ZERO-KNOWLEDGE: Verifier learns nothing about x beyond its existence
package schnorr

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/zkdpop/zkdpop-go/pkg/crypto/curve"
)

// Domain separation constants for hash functions.
// These prevent cross-protocol attacks by ensuring hashes computed in different
// contexts cannot be confused or reused.
const (
	// DomainChallenge is the domain separator for challenge derivation.
	// Format: H(DomainChallenge || T || PK || ctx)
	DomainChallenge = "zkdpop/1/chal"

	// DomainContext is the domain separator for context derivation.
	// Format: H(DomainContext || aud || path || method || timeslice || server_ephemeral)
	DomainContext = "zkdpop/1/ctx"
)

// VerificationResult contains the result of Schnorr verification
type VerificationResult struct {
	Valid   bool
	Error   error
	Context []byte // The computed context for debugging
}

// VerifySchnorr verifies a Schnorr identification proof.
//
// This is the core verification step of the Schnorr protocol. It checks that:
//
//	s*G == T + c*PK
//
// Where:
//   - s: response scalar (computed by prover as r + c*x mod q)
//   - G: generator point of the elliptic curve
//   - T: commitment point (computed by prover as r*G)
//   - c: challenge scalar (derived from transcript)
//   - PK: public key point (PK = x*G where x is the secret key)
//
// The equation holds if and only if the prover knows the secret key x.
//
// Security note: This function validates all inputs before computation to prevent
// invalid curve attacks (points not on curve) and small subgroup attacks (identity point).
func VerifySchnorr(crv curve.Curve, pk, T, c, s []byte) (*VerificationResult, error) {
	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 1: Parse all cryptographic components from byte representations
	// ═══════════════════════════════════════════════════════════════════════════

	// Parse the public key PK = x*G (the prover's long-term public key)
	PK, err := crv.ParsePoint(pk)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid public key: %w", err)}, nil
	}

	// Parse the commitment point T = r*G (the prover's ephemeral commitment)
	TT, err := crv.ParsePoint(T)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid commitment point: %w", err)}, nil
	}

	// Parse the challenge scalar c (derived from the protocol transcript)
	cs, err := crv.ParseScalar(c)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid challenge scalar: %w", err)}, nil
	}

	// Parse the response scalar s = r + c*x mod q (the prover's response)
	ss, err := crv.ParseScalar(s)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid response scalar: %w", err)}, nil
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 2: Validate points are on curve and not the identity element
	// ═══════════════════════════════════════════════════════════════════════════
	// This prevents invalid curve attacks and ensures we're working with valid
	// group elements. Accepting the identity point would allow trivial forgeries.

	if err := crv.ValidatePoint(PK); err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid public key point: %w", err)}, nil
	}

	if err := crv.ValidatePoint(TT); err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid commitment point: %w", err)}, nil
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 3: Compute LEFT side of verification equation: s*G
	// ═══════════════════════════════════════════════════════════════════════════
	// This is a scalar multiplication of the response s with the generator G.
	// If the prover is honest: s*G = (r + c*x)*G = r*G + c*x*G = T + c*PK

	left := crv.ScalarBaseMult(ss)
	if left == nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("failed to compute s*G")}, nil
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 4: Compute RIGHT side of verification equation: T + c*PK
	// ═══════════════════════════════════════════════════════════════════════════

	// First compute c*PK (scalar multiplication of challenge with public key)
	cPK := crv.ScalarMult(PK, cs)
	if cPK == nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("failed to compute c*PK")}, nil
	}

	// Then add T + c*PK (point addition)
	right := crv.Add(TT, cPK)
	if right == nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("failed to compute T + c*PK")}, nil
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 5: Compare left and right sides
	// ═══════════════════════════════════════════════════════════════════════════
	// The proof is valid if and only if: s*G == T + c*PK
	// This can only be true if the prover knows x such that PK = x*G

	valid := left.Equal(right)

	return &VerificationResult{
		Valid: valid,
		Error: nil,
	}, nil
}

// DeriveChallenge computes the Fiat-Shamir challenge scalar.
//
// In the interactive Schnorr protocol, the verifier sends a random challenge c.
// In the non-interactive variant (Fiat-Shamir heuristic), we derive c deterministically
// from the protocol transcript using a hash function:
//
//	c = H(DomainChallenge || T || PK || ctx) mod q
//
// Where:
//   - DomainChallenge: domain separator to prevent cross-protocol attacks
//   - T: commitment point (serialized)
//   - PK: public key point (serialized)
//   - ctx: context binding (audience, path, method, timeslice, server ephemeral)
//   - q: order of the elliptic curve group
//
// The context binding is crucial for security - it prevents the same proof from
// being replayed across different requests or to different audiences.
//
// Security: The hash output is reduced mod q. Since SHA-256 outputs 256 bits and
// curve orders are ~256 bits, this introduces negligible bias (< 2^-128).
func DeriveChallenge(crv curve.Curve, T, PK, ctxBytes []byte) ([]byte, error) {
	// Create hash with domain separation prefix
	// Domain separation ensures this hash cannot collide with hashes from other
	// protocols or contexts, even if they use the same inputs
	h := sha256.New()
	h.Write([]byte(DomainChallenge)) // "zkdpop/1/chal"
	h.Write(T)                       // Commitment point
	h.Write(PK)                      // Public key
	h.Write(ctxBytes)                // Request context (aud, path, method, etc.)

	hash := h.Sum(nil) // 32-byte SHA-256 digest

	// Reduce the 256-bit hash to a scalar in [0, q-1]
	// This is done by interpreting the hash as a big-endian integer and taking mod q
	challenge := new(big.Int).SetBytes(hash)
	challenge.Mod(challenge, crv.Order())

	// Serialize the scalar with proper zero-padding to curve's scalar size
	return padToOrderBytes(challenge, crv), nil
}

// DeriveContext creates a cryptographic binding between the Schnorr proof and
// the specific HTTP request being authenticated.
//
// The context hash includes:
//   - aud: intended audience (e.g., "api.example.com")
//   - path: HTTP request path (e.g., "/api/resource")
//   - method: HTTP method (e.g., "POST")
//   - timeslice: truncated timestamp for replay window
//   - serverEphemeral: 32 random bytes from server (prevents precomputation)
//
// This binding prevents several attacks:
//   - REPLAY: timeslice + serverEphemeral ensure freshness
//   - CROSS-SITE: audience binding prevents using proof for different service
//   - METHOD CONFUSION: method binding prevents GET proof used for POST
//   - PATH CONFUSION: path binding prevents /read proof used for /write
//
// The serverEphemeral is critical: without it, an attacker could precompute
// proofs for future timeslices. The random value forces the proof to be
// computed interactively with the server.
func DeriveContext(aud, path, method, timeslice string, serverEphemeral []byte) []byte {
	h := sha256.New()
	h.Write([]byte(DomainContext)) // Domain separator: "zkdpop/1/ctx"
	h.Write([]byte(aud))           // Audience/service identifier
	h.Write([]byte(path))          // HTTP request path
	h.Write([]byte(method))        // HTTP method (GET, POST, etc.)
	h.Write([]byte(timeslice))     // Time window (minute granularity)
	h.Write(serverEphemeral)       // Server-provided randomness

	return h.Sum(nil) // Returns 32-byte context hash
}

// FullVerifySchnorr performs end-to-end Schnorr verification with context binding.
//
// This is the main entry point for verifying zkDPoP authentication proofs.
// It combines context derivation, challenge computation, and proof verification
// into a single operation.
//
// The verification flow:
//  1. Derive context hash from request parameters
//  2. Compute challenge c = H(T || PK || ctx) mod q
//  3. Verify Schnorr equation: s*G == T + c*PK
//
// Parameters:
//   - crv: elliptic curve (secp256k1 or ristretto255)
//   - pk: prover's public key
//   - T: commitment point from prover
//   - s: response scalar from prover
//   - aud, path, method, timeslice, serverEphemeral: context binding parameters
//
// Returns VerificationResult with Valid=true if proof is correct.
func FullVerifySchnorr(crv curve.Curve, pk, T []byte, s []byte, aud, path, method, timeslice string, serverEphemeral []byte) (*VerificationResult, error) {
	// Step 1: Derive context hash that binds proof to this specific request
	ctx := DeriveContext(aud, path, method, timeslice, serverEphemeral)

	// Step 2: Compute challenge using Fiat-Shamir heuristic
	// c = H(T || PK || ctx) mod q
	c, err := DeriveChallenge(crv, T, pk, ctx)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("failed to derive challenge: %w", err)}, nil
	}

	// Step 3: Verify the Schnorr equation: s*G == T + c*PK
	result, err := VerifySchnorr(crv, pk, T, c, s)
	if err != nil {
		return nil, err
	}

	// Include context in result for debugging/logging
	result.Context = ctx

	return result, nil
}

// padToOrderBytes converts a big.Int to a fixed-size byte slice.
//
// Scalars must be serialized with consistent length for cryptographic operations.
// This function ensures the output is always the correct size for the curve's
// scalar field (32 bytes for secp256k1 and ristretto255).
//
// Example: scalar 0x01 becomes [0,0,0,...,0,1] (32 bytes, big-endian)
func padToOrderBytes(num *big.Int, crv curve.Curve) []byte {
	orderBytes := (crv.Order().BitLen() + 7) / 8 // Round up to nearest byte
	bytes := num.Bytes()                         // big.Int.Bytes() is big-endian, no leading zeros

	// Pad with leading zeros if necessary
	if len(bytes) < orderBytes {
		padded := make([]byte, orderBytes)
		copy(padded[orderBytes-len(bytes):], bytes) // Right-align (big-endian)
		return padded
	}

	return bytes
}

// GenerateCommitment creates the prover's commitment for Schnorr identification.
//
// This is STEP 1 of the Schnorr protocol (from the prover's perspective):
//  1. Generate a cryptographically secure random nonce r
//  2. Compute the commitment T = r*G
//  3. Send T to the verifier (keep r secret!)
//
// The nonce r MUST be:
//   - Truly random (use crypto/rand, never math/rand)
//   - Used only once (nonce = "number used once")
//   - Kept secret until the response is computed
//
// SECURITY WARNING: Reusing r for different challenges leaks the private key!
// If the same r is used with challenges c1 and c2, an attacker can compute:
//
//	x = (s1 - s2) / (c1 - c2) mod q
//
// Returns:
//   - T: commitment point (send to verifier)
//   - r: random scalar (keep secret, use in ComputeResponse)
func GenerateCommitment(crv curve.Curve) (T []byte, r curve.Scalar, err error) {
	// Generate cryptographically secure random scalar r ∈ [1, q-1]
	r, err = crv.GenerateScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}

	// Compute commitment T = r*G (scalar multiplication with generator)
	TPoint := crv.ScalarBaseMult(r)
	if TPoint == nil {
		return nil, nil, fmt.Errorf("failed to compute commitment point")
	}

	// Serialize commitment point for transmission
	T = TPoint.Bytes()
	return T, r, nil
}

// ComputeResponse computes the prover's response to the verifier's challenge.
//
// This is STEP 3 of the Schnorr protocol (from the prover's perspective):
//
//	s = r + c*x mod q
//
// Where:
//   - r: random nonce from GenerateCommitment (kept secret)
//   - c: challenge from verifier (received in STEP 2)
//   - x: prover's private key (long-term secret)
//   - q: order of the elliptic curve group
//
// The response s can be sent to the verifier - it reveals nothing about x
// because r acts as a one-time pad (assuming r is truly random and unique).
//
// Mathematical intuition:
//   - s = r + c*x looks like "private key x encrypted with one-time pad r"
//   - Without knowing r, the verifier cannot extract x from s
//   - But the verifier CAN check s*G == T + c*PK (which proves knowledge of x)
func ComputeResponse(crv curve.Curve, r, c, x curve.Scalar) (curve.Scalar, error) {
	// Compute c * x (challenge times private key)
	cx := new(big.Int).Mul(c.BigInt(), x.BigInt())
	cx.Mod(cx, crv.Order()) // Reduce mod q

	// Compute s = r + c*x (response scalar)
	rcx := new(big.Int).Add(r.BigInt(), cx)
	rcx.Mod(rcx, crv.Order()) // Reduce mod q

	// Convert back to curve scalar type
	return crv.ParseScalar(padToOrderBytes(rcx, crv))
}