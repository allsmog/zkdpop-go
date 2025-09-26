package curve

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/gtank/ristretto255"
)

// Ristretto255Point represents a point in the Ristretto255 prime-order group.
type Ristretto255Point struct {
	point *ristretto255.Element
}

// Bytes returns the canonical 32-byte encoding of the point.
func (p *Ristretto255Point) Bytes() []byte {
	if p == nil || p.point == nil {
		return nil
	}

	encoded := p.point.Encode(nil)
	out := make([]byte, len(encoded))
	copy(out, encoded)
	return out
}

// Equal reports whether two points are identical.
func (p *Ristretto255Point) Equal(other Point) bool {
	otherR, ok := other.(*Ristretto255Point)
	if !ok {
		return false
	}

	switch {
	case p == nil && otherR == nil:
		return true
	case p == nil || otherR == nil:
		return false
	}

	return p.point.Equal(otherR.point) == 1
}

// IsIdentity reports whether the point is the identity element.
func (p *Ristretto255Point) IsIdentity() bool {
	if p == nil || p.point == nil {
		return true
	}

	identity := ristretto255.NewIdentityElement()
	return p.point.Equal(identity) == 1
}

// Ristretto255Scalar represents a scalar modulo the Ristretto255 group order.
type Ristretto255Scalar struct {
	scalar *ristretto255.Scalar
}

// Bytes returns the canonical 32-byte little-endian encoding of the scalar.
func (s *Ristretto255Scalar) Bytes() []byte {
	if s == nil || s.scalar == nil {
		return nil
	}

	le := s.scalar.Bytes()
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return be
}

// BigInt returns the scalar value as a big.Int.
func (s *Ristretto255Scalar) BigInt() *big.Int {
	if s == nil || s.scalar == nil {
		return big.NewInt(0)
	}

	return new(big.Int).SetBytes(s.Bytes())
}

// Ristretto255Curve implements the Curve interface for the Ristretto group.
type Ristretto255Curve struct{}

// NewRistretto255 creates a new Ristretto255 curve instance.
func NewRistretto255() Curve {
	return &Ristretto255Curve{}
}

// Name returns the canonical group name.
func (c *Ristretto255Curve) Name() string {
	return "ristretto255"
}

// ParsePoint decodes a canonical 32-byte Ristretto point encoding.
func (c *Ristretto255Curve) ParsePoint(b []byte) (Point, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidPoint, len(b))
	}

	elem := ristretto255.NewIdentityElement()
	if _, err := elem.SetCanonicalBytes(b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPoint, err)
	}

	return &Ristretto255Point{point: elem}, nil
}

// ParseScalar decodes a canonical scalar encoding.
func (c *Ristretto255Curve) ParseScalar(b []byte) (Scalar, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidScalar, len(b))
	}

	bi := new(big.Int).SetBytes(b)
	if bi.Sign() <= 0 || bi.Cmp(c.Order()) >= 0 {
		return nil, fmt.Errorf("%w: scalar out of range", ErrInvalidScalar)
	}

	le := make([]byte, 32)
	be := bi.FillBytes(make([]byte, 32))
	for i := range be {
		le[i] = be[len(be)-1-i]
	}

	sc := ristretto255.NewScalar()
	if _, err := sc.SetCanonicalBytes(le); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidScalar, err)
	}

	return &Ristretto255Scalar{scalar: sc}, nil
}

// ScalarBaseMult returns s*B, where B is the canonical generator.
func (c *Ristretto255Curve) ScalarBaseMult(s Scalar) Point {
	ristScalar, ok := s.(*Ristretto255Scalar)
	if !ok || ristScalar.scalar == nil {
		return nil
	}

	elem := ristretto255.NewIdentityElement()
	elem.ScalarBaseMult(ristScalar.scalar)
	return &Ristretto255Point{point: elem}
}

// ScalarMult computes s * P for the provided point and scalar.
func (c *Ristretto255Curve) ScalarMult(p Point, s Scalar) Point {
	ristPoint, ok := p.(*Ristretto255Point)
	if !ok || ristPoint.point == nil {
		return nil
	}
	ristScalar, ok := s.(*Ristretto255Scalar)
	if !ok || ristScalar.scalar == nil {
		return nil
	}

	elem := ristretto255.NewIdentityElement()
	elem.ScalarMult(ristScalar.scalar, ristPoint.point)
	return &Ristretto255Point{point: elem}
}

// Add returns P + Q for two group elements.
func (c *Ristretto255Curve) Add(p, q Point) Point {
	rp, ok := p.(*Ristretto255Point)
	if !ok || rp.point == nil {
		return nil
	}
	rq, ok := q.(*Ristretto255Point)
	if !ok || rq.point == nil {
		return nil
	}

	elem := ristretto255.NewIdentityElement()
	elem.Add(rp.point, rq.point)
	return &Ristretto255Point{point: elem}
}

// Order returns the order of the Ristretto255 group.
func (c *Ristretto255Curve) Order() *big.Int {
	// l = 2^252 + 27742317777372353535851937790883648493
	order := new(big.Int).Lsh(big.NewInt(1), 252)
	addend, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	order.Add(order, addend)
	return order
}

// GenerateScalar returns a uniformly random scalar.
func (c *Ristretto255Curve) GenerateScalar() (Scalar, error) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}

	sc := ristretto255.NewScalar()
	if _, err := sc.SetUniformBytes(seed); err != nil {
		return nil, fmt.Errorf("failed to derive scalar: %w", err)
	}

	return &Ristretto255Scalar{scalar: sc}, nil
}

// ValidatePoint ensures the point is non-identity and properly encoded.
func (c *Ristretto255Curve) ValidatePoint(p Point) error {
	rp, ok := p.(*Ristretto255Point)
	if !ok || rp.point == nil {
		return ErrInvalidPoint
	}

	if rp.IsIdentity() {
		return ErrIdentityPoint
	}

	return nil
}
