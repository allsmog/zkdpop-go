package schnorr

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/zkdpop/zkdpop-go/pkg/crypto/curve"
)

// Domain separation constants for hash functions
const (
	DomainChallenge = "zkdpop/1/chal"
	DomainContext   = "zkdpop/1/ctx"
)

// VerificationResult contains the result of Schnorr verification
type VerificationResult struct {
	Valid   bool
	Error   error
	Context []byte // The computed context for debugging
}

// VerifySchnorr verifies a Schnorr identification proof
// Verifies that s*G == T + c*PK where:
// - s is the response scalar
// - G is the generator point  
// - T is the commitment point
// - c is the challenge scalar
// - PK is the public key point
func VerifySchnorr(crv curve.Curve, pk, T, c, s []byte) (*VerificationResult, error) {
	// Parse all the components
	PK, err := crv.ParsePoint(pk)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid public key: %w", err)}, nil
	}

	TT, err := crv.ParsePoint(T)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid commitment point: %w", err)}, nil
	}

	cs, err := crv.ParseScalar(c)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid challenge scalar: %w", err)}, nil
	}

	ss, err := crv.ParseScalar(s)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid response scalar: %w", err)}, nil
	}

	// Validate points are on curve and not identity
	if err := crv.ValidatePoint(PK); err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid public key point: %w", err)}, nil
	}

	if err := crv.ValidatePoint(TT); err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("invalid commitment point: %w", err)}, nil
	}

	// Compute left side: s*G
	left := crv.ScalarBaseMult(ss)
	if left == nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("failed to compute s*G")}, nil
	}

	// Compute right side: T + c*PK
	cPK := crv.ScalarMult(PK, cs)
	if cPK == nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("failed to compute c*PK")}, nil
	}

	right := crv.Add(TT, cPK)
	if right == nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("failed to compute T + c*PK")}, nil
	}

	// Check if s*G == T + c*PK
	valid := left.Equal(right)

	return &VerificationResult{
		Valid: valid,
		Error: nil,
	}, nil
}

// DeriveChallenge computes the challenge scalar c = H(T || PK || ctx) mod q
// This follows the zkDPoP specification with domain separation
func DeriveChallenge(crv curve.Curve, T, PK, ctxBytes []byte) ([]byte, error) {
	// Domain separate the hash input
	h := sha256.New()
	h.Write([]byte(DomainChallenge))
	h.Write(T)
	h.Write(PK)
	h.Write(ctxBytes)

	hash := h.Sum(nil)

	// Reduce hash to scalar mod curve order
	challenge := new(big.Int).SetBytes(hash)
	challenge.Mod(challenge, crv.Order())

	// Convert back to bytes with proper padding
	return padToOrderBytes(challenge, crv), nil
}

// DeriveContext computes ctx = H(aud || path || method || timeslice || server_ephemeral)
// This binds the challenge to specific request parameters
func DeriveContext(aud, path, method, timeslice string, serverEphemeral []byte) []byte {
	h := sha256.New()
	h.Write([]byte(DomainContext))
	h.Write([]byte(aud))
	h.Write([]byte(path))
	h.Write([]byte(method))
	h.Write([]byte(timeslice))
	h.Write(serverEphemeral)

	return h.Sum(nil)
}

// FullVerifySchnorr performs complete Schnorr verification including context derivation
// This is the main verification function that should be used in production
func FullVerifySchnorr(crv curve.Curve, pk, T []byte, s []byte, aud, path, method, timeslice string, serverEphemeral []byte) (*VerificationResult, error) {
	// Derive context from request parameters
	ctx := DeriveContext(aud, path, method, timeslice, serverEphemeral)

	// Derive challenge from commitment, public key, and context
	c, err := DeriveChallenge(crv, T, pk, ctx)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Errorf("failed to derive challenge: %w", err)}, nil
	}

	// Perform Schnorr verification
	result, err := VerifySchnorr(crv, pk, T, c, s)
	if err != nil {
		return nil, err
	}

	// Add context to result for debugging
	result.Context = ctx

	return result, nil
}

// padToOrderBytes pads a big.Int to the byte length needed for the curve order
func padToOrderBytes(num *big.Int, crv curve.Curve) []byte {
	orderBytes := (crv.Order().BitLen() + 7) / 8 // Round up to nearest byte
	bytes := num.Bytes()

	if len(bytes) < orderBytes {
		padded := make([]byte, orderBytes)
		copy(padded[orderBytes-len(bytes):], bytes)
		return padded
	}

	return bytes
}

// GenerateCommitment generates a random commitment T = r*G for Schnorr identification
// Returns the commitment point T and the random scalar r
// The caller should keep r secret and use it to compute the response s = r + c*x
func GenerateCommitment(crv curve.Curve) (T []byte, r curve.Scalar, err error) {
	// Generate random scalar r
	r, err = crv.GenerateScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}

	// Compute T = r*G
	TPoint := crv.ScalarBaseMult(r)
	if TPoint == nil {
		return nil, nil, fmt.Errorf("failed to compute commitment point")
	}

	T = TPoint.Bytes()
	return T, r, nil
}

// ComputeResponse computes the Schnorr response s = r + c*x mod q
// where r is the commitment randomness, c is the challenge, and x is the private key
func ComputeResponse(crv curve.Curve, r, c, x curve.Scalar) (curve.Scalar, error) {
	// Compute c * x
	cx := new(big.Int).Mul(c.BigInt(), x.BigInt())
	cx.Mod(cx, crv.Order())

	// Compute r + c*x
	rcx := new(big.Int).Add(r.BigInt(), cx)
	rcx.Mod(rcx, crv.Order())

	// Convert back to scalar
	return crv.ParseScalar(padToOrderBytes(rcx, crv))
}