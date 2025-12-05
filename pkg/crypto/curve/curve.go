// Package curve provides abstract interfaces for elliptic curve cryptography
// operations used in the zkDPoP protocol.
//
// # Supported Curves
//
// The package supports two elliptic curve groups:
//
//   - secp256k1: The curve used by Bitcoin and Ethereum. A Koblitz curve with
//     efficient arithmetic. Points are 33 bytes (compressed) or 65 bytes
//     (uncompressed). Scalars are 32 bytes.
//
//   - ristretto255: A prime-order group built on Curve25519. Provides simpler
//     and safer APIs by abstracting away cofactor issues. Points and scalars
//     are both 32 bytes.
//
// # Elliptic Curve Basics
//
// An elliptic curve group consists of:
//   - A set of points on the curve (including a special "identity" point)
//   - A generator point G that generates the entire group
//   - A group order q (the number of points in the group)
//
// Key operations:
//   - Point Addition: P + Q = R (adding two points gives another point)
//   - Scalar Multiplication: s * P (adding P to itself s times)
//   - The "discrete log problem": given P and Q = s*P, finding s is hard
//
// # Security Properties
//
// The hardness of the discrete logarithm problem is what makes these curves
// useful for cryptography. Given a public key PK = x*G, an attacker cannot
// efficiently compute the private key x.
package curve

import (
	"fmt"
	"math/big"
)

// Point represents a point on an elliptic curve.
//
// In elliptic curve cryptography, points are the fundamental objects.
// A point is an (x, y) coordinate pair satisfying the curve equation,
// or the special "identity" point (point at infinity).
//
// For secp256k1: y² = x³ + 7 (mod p)
// For ristretto255: uses Curve25519's equation with ristretto encoding
type Point interface {
	// Bytes returns the canonical serialization of the point.
	// For secp256k1: 33 bytes (compressed format: 0x02/0x03 prefix + x-coordinate)
	// For ristretto255: 32 bytes (canonical ristretto encoding)
	Bytes() []byte

	// Equal checks if two points are equal.
	// This must be a constant-time comparison to prevent timing attacks.
	Equal(other Point) bool

	// IsIdentity checks if this is the identity point (point at infinity).
	// The identity point is the "zero" of the group: P + Identity = P
	// Proofs involving the identity point are often trivial/insecure.
	IsIdentity() bool
}

// Scalar represents a scalar value for curve operations.
//
// Scalars are integers modulo the curve order q. They are used as:
//   - Private keys (random scalar x where public key is x*G)
//   - Nonces (random scalar r in Schnorr commitment T = r*G)
//   - Challenges (hash output reduced mod q)
//   - Responses (s = r + c*x mod q in Schnorr)
//
// Valid scalars are in the range [1, q-1] (we exclude 0 for security).
type Scalar interface {
	// Bytes returns the scalar as a fixed-size byte slice.
	// For secp256k1: 32 bytes, big-endian
	// For ristretto255: 32 bytes, big-endian (converted from internal little-endian)
	Bytes() []byte

	// BigInt returns the scalar as a big.Int for arithmetic operations.
	BigInt() *big.Int
}

// Curve abstracts elliptic curve operations for different curves.
//
// This interface allows the zkDPoP protocol to work with multiple curve
// implementations. The two supported curves have different properties:
//
//   - secp256k1: Widely deployed, hardware wallet support, Bitcoin/Ethereum compatible
//   - ristretto255: Simpler API, no cofactor issues, modern design
//
// All implementations must be safe against:
//   - Invalid curve attacks (reject points not on curve)
//   - Small subgroup attacks (reject identity and low-order points)
//   - Timing attacks (use constant-time operations where possible)
type Curve interface {
	// Name returns the curve identifier (e.g., "secp256k1", "ristretto255").
	// This is included in JWT tokens to identify the ZK scheme used.
	Name() string

	// ParsePoint deserializes a point from bytes.
	// Validates that the point is on the curve and not malformed.
	// For secp256k1: accepts 33-byte compressed or 65-byte uncompressed format
	// For ristretto255: accepts 32-byte canonical encoding
	ParsePoint(b []byte) (Point, error)

	// ParseScalar deserializes a scalar from bytes.
	// Validates that the scalar is in range [1, q-1].
	// Rejects zero (which would produce the identity point in multiplications).
	ParseScalar(b []byte) (Scalar, error)

	// ScalarBaseMult computes s * G (scalar multiplication with generator).
	// This is the core operation for:
	//   - Computing public key from private key: PK = x * G
	//   - Computing commitment: T = r * G
	//   - Verification left side: s * G
	ScalarBaseMult(s Scalar) Point

	// ScalarMult computes s * P (scalar multiplication with arbitrary point).
	// Used in verification to compute c * PK (challenge times public key).
	ScalarMult(p Point, s Scalar) Point

	// Add computes P + Q (point addition).
	// Used in verification to compute T + c*PK.
	Add(p, q Point) Point

	// Order returns q, the order of the curve's group.
	// All scalar arithmetic is performed modulo q.
	// For secp256k1: q ≈ 2^256 (specifically: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
	// For ristretto255: q = 2^252 + 27742317777372353535851937790883648493
	Order() *big.Int

	// GenerateScalar creates a cryptographically secure random scalar.
	// Uses crypto/rand for randomness. Returns scalar in [1, q-1].
	// Used for generating private keys and commitment nonces.
	GenerateScalar() (Scalar, error)

	// ValidatePoint checks that a point is valid for cryptographic use.
	// Rejects:
	//   - Points not on the curve
	//   - The identity point (point at infinity)
	//   - Points in small subgroups (for curves with cofactor > 1)
	ValidatePoint(p Point) error
}

var (
	// ErrInvalidPoint indicates an invalid point
	ErrInvalidPoint = fmt.Errorf("invalid point")
	
	// ErrInvalidScalar indicates an invalid scalar
	ErrInvalidScalar = fmt.Errorf("invalid scalar")
	
	// ErrIdentityPoint indicates the point is the identity point
	ErrIdentityPoint = fmt.Errorf("point is identity")
	
	// ErrPointNotOnCurve indicates the point is not on the curve
	ErrPointNotOnCurve = fmt.Errorf("point is not on curve")
)