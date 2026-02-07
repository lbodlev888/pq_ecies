package pq_ecies

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	saltLen int = 16
	infoString string = "hybrid_ecies"
	eph256Len int = 65
)

type EncryptedMessage struct {
	ciphertext, nonce, ephPub, salt, mlkem_ciphertext []byte
}

func (e *EncryptedMessage) Bytes() []byte {
	//pattern: nonce, salt, ephPub, mlkem_ciphertext, ciphertext
	buffer := bytes.NewBuffer(nil)

	buffer.Write(e.nonce)
	buffer.Write(e.salt)
	buffer.Write(e.ephPub)
	buffer.Write(e.mlkem_ciphertext)
	buffer.Write(e.ciphertext)

	return buffer.Bytes()
}

func ParseEncryptedMessage(enc_message []byte) (*EncryptedMessage) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, enc_message)
	enc_message = enc_message[chacha20poly1305.NonceSize:]

	salt := make([]byte, saltLen)
	copy(salt, enc_message)
	enc_message = enc_message[saltLen:]

	ephPub := make([]byte, eph256Len)
	copy(ephPub, enc_message)
	enc_message = enc_message[eph256Len:]

	mlkem_ciphertext := make([]byte, mlkem.CiphertextSize768)
	copy(mlkem_ciphertext, enc_message)
	enc_message = enc_message[mlkem.CiphertextSize768:]

	ciphertext := make([]byte, len(enc_message))
	copy(ciphertext, enc_message)

	return &EncryptedMessage{
		nonce: nonce,
		salt: salt,
		ephPub: ephPub,
		mlkem_ciphertext: mlkem_ciphertext,
		ciphertext: ciphertext,
	}
}

func (k *PublicKeyPair) Encrypt(message []byte) (*EncryptedMessage, error) {
	eph_key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil { return nil, err }

	ecdhSharedSecret, err := eph_key.ECDH(k.pubKey)
	if err != nil { return nil, err }

	mlkemSharedSecret, mlkemCiphertext := k.encapsulationKey.Encapsulate()

	sharedSecret := append(ecdhSharedSecret, mlkemSharedSecret...)
	
	salt := make([]byte, saltLen)
	rand.Read(salt)

	encryption_key, err := hkdf.Key(sha256.New, sharedSecret, salt, infoString, chacha20poly1305.KeySize)
	if err != nil { return nil, err }

	nonce := make([]byte, chacha20poly1305.NonceSize)
	rand.Read(nonce)

	aead, err := chacha20poly1305.New(encryption_key)
	if err != nil { return nil, err }

	ciphertext := aead.Seal(nil, nonce, message, nil)
	return &EncryptedMessage{
		nonce: nonce,
		ciphertext: ciphertext,
		salt: salt,
		ephPub: eph_key.PublicKey().Bytes(),
		mlkem_ciphertext: mlkemCiphertext,
	}, nil
}

func (k *PrivateKeyPair) Decrypt(enc_message *EncryptedMessage) ([]byte, error) {
	ephPub, err := ecdh.P256().NewPublicKey(enc_message.ephPub)
	if err != nil { return nil, err }

	ecdhSharedSecret, err := k.privKey.ECDH(ephPub)
	if err != nil { return nil, err }

	mlkemSharedSecret, err := k.decapsulationKey.Decapsulate(enc_message.mlkem_ciphertext)
	if err != nil { return nil, err }

	sharedSecret := append(ecdhSharedSecret, mlkemSharedSecret...)

	encryption_key, err := hkdf.Key(sha256.New, sharedSecret, enc_message.salt, infoString, chacha20poly1305.KeySize)
	if err != nil { return nil, err }

	aead, err := chacha20poly1305.New(encryption_key)
	if err != nil { return nil, err }

	return aead.Open(nil, enc_message.nonce, enc_message.ciphertext, nil)
}
