package curve

import (
	"fmt"
	"math/big"
)

// Point represents a point on an elliptic curve
type Point interface {
	// Bytes returns the compressed point encoding
	Bytes() []byte
	// Equal checks if two points are equal
	Equal(other Point) bool
	// IsIdentity checks if this is the identity point
	IsIdentity() bool
}

// Scalar represents a scalar value for curve operations
type Scalar interface {
	// Bytes returns the scalar as a byte slice
	Bytes() []byte
	// BigInt returns the scalar as a big.Int
	BigInt() *big.Int
}

// Curve abstracts elliptic curve operations for different curves
type Curve interface {
	// Name returns the curve name (e.g., "secp256k1", "ristretto255")
	Name() string
	
	// ParsePoint parses a point from bytes (compressed or uncompressed)
	ParsePoint(b []byte) (Point, error)
	
	// ParseScalar parses a scalar from bytes
	ParseScalar(b []byte) (Scalar, error)
	
	// ScalarBaseMult computes s * G (scalar multiplication with base point)
	ScalarBaseMult(s Scalar) Point
	
	// ScalarMult computes s * P (scalar multiplication with point P)
	ScalarMult(p Point, s Scalar) Point
	
	// Add adds two points: P + Q
	Add(p, q Point) Point
	
	// Order returns the order of the curve (number of points)
	Order() *big.Int
	
	// GenerateScalar generates a random scalar
	GenerateScalar() (Scalar, error)
	
	// ValidatePoint validates that a point is on the curve and not the identity
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