package curve

import "testing"

func TestFromName(t *testing.T) {
	curves := map[string]string{
		"secp256k1":    "secp256k1",
		"ristretto255": "ristretto255",
	}

	for input, expected := range curves {
		curve, err := FromName(input)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", input, err)
		}

		if curve.Name() != expected {
			t.Fatalf("expected %s, got %s", expected, curve.Name())
		}
	}

	if _, err := FromName("unknown"); err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}
