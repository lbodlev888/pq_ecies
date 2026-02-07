package keys

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
)

const (
	decapsLen int = 64
	encapsLen int = 1184
	ecPrivLen int = 32
	ecPubLen int = 65
)

type PrivateKeyPair struct {
	privKey *ecdh.PrivateKey
	decapsulationKey *mlkem.DecapsulationKey768
}

func GenerateKeyPair() (*PrivateKeyPair, error) {
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil { return nil, err }

	decaps, err := mlkem.GenerateKey768()
	if err != nil { return nil, err }

	return &PrivateKeyPair{
		privKey: privKey,
		decapsulationKey: decaps,
	}, nil
}

func (k *PrivateKeyPair) Bytes() []byte {
	return append(k.decapsulationKey.Bytes(), k.privKey.Bytes()...)
}

func (k *PrivateKeyPair) Public() (*PublicKeyPair, error) {
	return &PublicKeyPair{
		pubKey: k.privKey.PublicKey(),
		encapsulationKey: k.decapsulationKey.EncapsulationKey(),
	}, nil
}

func LoadPrivate(raw []byte) (*PrivateKeyPair, error) {
	if len(raw) < decapsLen + ecPrivLen {
		return nil, fmt.Errorf("Input data is too small")
	}

	decapsB := make([]byte, decapsLen)
	copy(decapsB, raw)
	raw = raw[decapsLen:]

	ecB := make([]byte, ecPrivLen)
	copy(ecB, raw)

	decaps, err := mlkem.NewDecapsulationKey768(decapsB)
	if err != nil { return nil, err }

	ec, err := ecdh.P256().NewPrivateKey(ecB)
	if err != nil { return nil, err }

	return &PrivateKeyPair{
		decapsulationKey: decaps,
		privKey: ec,
	}, nil
}
