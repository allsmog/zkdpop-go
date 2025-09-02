package curve

import (
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Secp256k1Point represents a point on the secp256k1 curve
type Secp256k1Point struct {
	point *btcec.PublicKey
}

// Bytes returns the compressed point encoding (33 bytes)
func (p *Secp256k1Point) Bytes() []byte {
	if p.point == nil {
		return nil
	}
	return p.point.SerializeCompressed()
}

// Equal checks if two points are equal
func (p *Secp256k1Point) Equal(other Point) bool {
	otherSecp, ok := other.(*Secp256k1Point)
	if !ok {
		return false
	}
	if p.point == nil && otherSecp.point == nil {
		return true
	}
	if p.point == nil || otherSecp.point == nil {
		return false
	}
	return p.point.IsEqual(otherSecp.point)
}

// IsIdentity checks if this is the identity point (point at infinity)
func (p *Secp256k1Point) IsIdentity() bool {
	// btcec doesn't directly expose identity check, so we check for nil
	// In practice, we'll reject identity points during parsing
	return p.point == nil
}

// Secp256k1Scalar represents a scalar for secp256k1 operations
type Secp256k1Scalar struct {
	scalar *big.Int
}

// Bytes returns the scalar as a 32-byte slice (big-endian)
func (s *Secp256k1Scalar) Bytes() []byte {
	if s.scalar == nil {
		return nil
	}
	bytes := s.scalar.Bytes()
	// Ensure 32-byte length
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		return padded
	}
	return bytes
}

// BigInt returns the scalar as a big.Int
func (s *Secp256k1Scalar) BigInt() *big.Int {
	return new(big.Int).Set(s.scalar)
}

// Secp256k1Curve implements the Curve interface for secp256k1
type Secp256k1Curve struct{}

// NewSecp256k1 creates a new secp256k1 curve instance
func NewSecp256k1() Curve {
	return &Secp256k1Curve{}
}

// Name returns the curve name
func (c *Secp256k1Curve) Name() string {
	return "secp256k1"
}

// ParsePoint parses a point from bytes (33-byte compressed or 65-byte uncompressed)
func (c *Secp256k1Curve) ParsePoint(b []byte) (Point, error) {
	if len(b) == 0 {
		return nil, ErrInvalidPoint
	}
	
	pubKey, err := btcec.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPoint, err)
	}
	
	point := &Secp256k1Point{point: pubKey}
	
	// Validate the point is not identity and is on curve
	if err := c.ValidatePoint(point); err != nil {
		return nil, err
	}
	
	return point, nil
}

// ParseScalar parses a scalar from bytes (32 bytes, big-endian)
func (c *Secp256k1Curve) ParseScalar(b []byte) (Scalar, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidScalar, len(b))
	}
	
	scalar := new(big.Int).SetBytes(b)
	
	// Ensure scalar is in valid range [1, n-1] where n is the curve order
	if scalar.Sign() <= 0 || scalar.Cmp(c.Order()) >= 0 {
		return nil, fmt.Errorf("%w: scalar out of range", ErrInvalidScalar)
	}
	
	return &Secp256k1Scalar{scalar: scalar}, nil
}

// ScalarBaseMult computes s * G (scalar multiplication with generator)
func (c *Secp256k1Curve) ScalarBaseMult(s Scalar) Point {
	secp256k1Scalar, ok := s.(*Secp256k1Scalar)
	if !ok {
		return nil
	}
	
	// Create private key from scalar and get the public key (which is s * G)
	privKey, pubKey := btcec.PrivKeyFromBytes(secp256k1Scalar.Bytes())
	_ = privKey // We only need the public key
	
	return &Secp256k1Point{point: pubKey}
}

// ScalarMult computes s * P (scalar multiplication)
func (c *Secp256k1Curve) ScalarMult(p Point, s Scalar) Point {
	secp256k1Point, ok := p.(*Secp256k1Point)
	if !ok {
		return nil
	}
	secp256k1Scalar, ok := s.(*Secp256k1Scalar)
	if !ok {
		return nil
	}
	
	// Get point coordinates
	px, py := secp256k1Point.point.X(), secp256k1Point.point.Y()
	
	// Perform scalar multiplication: s * P
	rx, ry := btcec.S256().ScalarMult(px, py, secp256k1Scalar.scalar.Bytes())
	
	// Create public key from coordinates using the curve's point creation
	pubKey, err := btcec.ParsePubKey(append([]byte{0x04}, append(rx.FillBytes(make([]byte, 32)), ry.FillBytes(make([]byte, 32))...)...))
	if err != nil {
		return nil
	}
	return &Secp256k1Point{point: pubKey}
}

// Add adds two points: P + Q
func (c *Secp256k1Curve) Add(p, q Point) Point {
	secp256k1P, ok := p.(*Secp256k1Point)
	if !ok {
		return nil
	}
	secp256k1Q, ok := q.(*Secp256k1Point)
	if !ok {
		return nil
	}
	
	// Get point coordinates
	px, py := secp256k1P.point.X(), secp256k1P.point.Y()
	qx, qy := secp256k1Q.point.X(), secp256k1Q.point.Y()
	
	// Add the points
	rx, ry := btcec.S256().Add(px, py, qx, qy)
	
	// Create public key from coordinates using the curve's point creation
	pubKey, err := btcec.ParsePubKey(append([]byte{0x04}, append(rx.FillBytes(make([]byte, 32)), ry.FillBytes(make([]byte, 32))...)...))
	if err != nil {
		return nil
	}
	return &Secp256k1Point{point: pubKey}
}

// Order returns the order of the secp256k1 curve
func (c *Secp256k1Curve) Order() *big.Int {
	return btcec.S256().N
}

// GenerateScalar generates a cryptographically secure random scalar
func (c *Secp256k1Curve) GenerateScalar() (Scalar, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate scalar: %w", err)
	}
	
	// Convert the private key to a scalar - use the raw bytes
	scalarBytes := privKey.Serialize()
	scalar := new(big.Int).SetBytes(scalarBytes)
	return &Secp256k1Scalar{scalar: scalar}, nil
}

// ValidatePoint validates that a point is on the curve and not the identity
func (c *Secp256k1Curve) ValidatePoint(p Point) error {
	secp256k1Point, ok := p.(*Secp256k1Point)
	if !ok {
		return ErrInvalidPoint
	}
	
	if secp256k1Point.point == nil {
		return ErrIdentityPoint
	}
	
	// Check if point is on curve (btcec.ParsePubKey already validates this)
	// But we can double-check by verifying the curve equation
	curve := btcec.S256()
	if !curve.IsOnCurve(secp256k1Point.point.X(), secp256k1Point.point.Y()) {
		return ErrPointNotOnCurve
	}
	
	// Check if point is the identity (point at infinity)
	// For secp256k1, we reject (0,0) and equivalent representations
	if secp256k1Point.point.X().Sign() == 0 && secp256k1Point.point.Y().Sign() == 0 {
		return ErrIdentityPoint
	}
	
	return nil
}