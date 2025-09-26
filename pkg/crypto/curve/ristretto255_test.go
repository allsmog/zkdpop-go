package curve

import "testing"

func TestRistrettoGenerateScalar(t *testing.T) {
	curve := NewRistretto255()

	scalar, err := curve.GenerateScalar()
	if err != nil {
		t.Fatalf("failed to generate scalar: %v", err)
	}

	if scalar.Bytes() == nil {
		t.Fatal("scalar bytes should not be nil")
	}

	if scalar.BigInt().Sign() <= 0 {
		t.Fatal("expected positive scalar")
	}

	if scalar.BigInt().Cmp(curve.Order()) >= 0 {
		t.Fatal("scalar should be reduced modulo curve order")
	}
}

func TestRistrettoScalarBaseMultAndParse(t *testing.T) {
	curve := NewRistretto255()

	scalar, err := curve.GenerateScalar()
	if err != nil {
		t.Fatalf("failed to generate scalar: %v", err)
	}

	point := curve.ScalarBaseMult(scalar)
	if point == nil {
		t.Fatal("scalar base mult returned nil point")
	}

	if err := curve.ValidatePoint(point); err != nil {
		t.Fatalf("generated point did not validate: %v", err)
	}

	encodedPoint := point.Bytes()
	parsedPoint, err := curve.ParsePoint(encodedPoint)
	if err != nil {
		t.Fatalf("failed to parse point: %v", err)
	}

	if !parsedPoint.Equal(point) {
		t.Fatal("parsed point mismatch")
	}

	encodedScalar := scalar.Bytes()
	parsedScalar, err := curve.ParseScalar(encodedScalar)
	if err != nil {
		t.Fatalf("failed to parse scalar: %v", err)
	}

	if parsedScalar.BigInt().Cmp(scalar.BigInt()) != 0 {
		t.Fatal("parsed scalar mismatch")
	}
}
