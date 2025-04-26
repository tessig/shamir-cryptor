package shamir

import (
	"crypto/rand"
	"fmt"

	"github.com/hashicorp/vault/shamir"
)

func Create(parts, threshold, keysize int) ([]byte, [][]byte, error) {
	secret := make([]byte, keysize)

	if _, err := rand.Read(secret); err != nil {
		return nil, nil, fmt.Errorf("failed to create random key: %w", err)
	}

	shares, err := shamir.Split(secret, parts, threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to split key: %w", err)
	}

	return secret, shares, nil
}

func Combine(shares [][]byte) ([]byte, error) {
	reconstructedSecret, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("failed to combine parts: %w", err)
	}

	return reconstructedSecret, nil
}
