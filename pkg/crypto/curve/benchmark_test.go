package curve

import (
	"testing"
)

func BenchmarkSecp256k1_GenerateScalar(b *testing.B) {
	curve := NewSecp256k1()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := curve.GenerateScalar()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSecp256k1_ScalarBaseMult(b *testing.B) {
	curve := NewSecp256k1()
	scalar, _ := curve.GenerateScalar()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		point := curve.ScalarBaseMult(scalar)
		if point == nil {
			b.Fatal("point should not be nil")
		}
	}
}

func BenchmarkSecp256k1_ScalarMult(b *testing.B) {
	curve := NewSecp256k1()
	scalar1, _ := curve.GenerateScalar()
	scalar2, _ := curve.GenerateScalar()
	point := curve.ScalarBaseMult(scalar1)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result := curve.ScalarMult(point, scalar2)
		if result == nil {
			b.Fatal("result should not be nil")
		}
	}
}

func BenchmarkSecp256k1_Add(b *testing.B) {
	curve := NewSecp256k1()
	s1, _ := curve.GenerateScalar()
	s2, _ := curve.GenerateScalar()
	p1 := curve.ScalarBaseMult(s1)
	p2 := curve.ScalarBaseMult(s2)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sum := curve.Add(p1, p2)
		if sum == nil {
			b.Fatal("sum should not be nil")
		}
	}
}

func BenchmarkSecp256k1_ParsePoint(b *testing.B) {
	curve := NewSecp256k1()
	scalar, _ := curve.GenerateScalar()
	point := curve.ScalarBaseMult(scalar)
	pointBytes := point.Bytes()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := curve.ParsePoint(pointBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSecp256k1_ParseScalar(b *testing.B) {
	curve := NewSecp256k1()
	scalar, _ := curve.GenerateScalar()
	scalarBytes := scalar.Bytes()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := curve.ParseScalar(scalarBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSecp256k1_ValidatePoint(b *testing.B) {
	curve := NewSecp256k1()
	scalar, _ := curve.GenerateScalar()
	point := curve.ScalarBaseMult(scalar)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := curve.ValidatePoint(point)
		if err != nil {
			b.Fatal(err)
		}
	}
}