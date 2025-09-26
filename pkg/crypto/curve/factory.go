package curve

import (
	"fmt"
	"strings"
)

// FromName returns a Curve implementation that matches the provided name.
func FromName(name string) (Curve, error) {
	switch strings.ToLower(name) {
	case "secp256k1":
		return NewSecp256k1(), nil
	case "ristretto255":
		return NewRistretto255(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

// SupportedCurves lists the curve identifiers understood by FromName.
func SupportedCurves() []string {
	return []string{"secp256k1", "ristretto255"}
}
