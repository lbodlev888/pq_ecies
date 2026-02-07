package pq_ecies

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"fmt"
)

type PublicKeyPair struct {
	pubKey *ecdh.PublicKey
	encapsulationKey *mlkem.EncapsulationKey768
}

func (k *PublicKeyPair) Bytes() []byte {
	return append(k.encapsulationKey.Bytes(), k.pubKey.Bytes()...)
}

func LoadPublic(raw []byte) (*PublicKeyPair, error) {
	if len(raw) < encapsLen + ecPubLen {
		return nil, fmt.Errorf("Input data is too small")
	}

	encapsB := make([]byte, encapsLen)
	copy(encapsB, raw)
	raw = raw[encapsLen:]

	ecB := make([]byte, ecPubLen)
	copy(ecB, raw)

	encaps, err := mlkem.NewEncapsulationKey768(encapsB)
	if err != nil { return nil, err }

	ec, err := ecdh.P256().NewPublicKey(ecB)
	if err != nil { return nil, err }

	return &PublicKeyPair{
		encapsulationKey: encaps,
		pubKey: ec,
	}, nil
}
