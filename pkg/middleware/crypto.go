package middleware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

func computeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, blindIndexKey)
	mac.Write(data)
	return mac.Sum(nil)
}

func generateAndWrapDEK(pubKey *rsa.PublicKey) (dek []byte, wrappedDek []byte, err error) {
	dek = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, err
	}

	wrappedDek, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, dek, nil)
	if err != nil {
		return nil, nil, err
	}

	return dek, wrappedDek, nil
}

func unwrapDEK(wrappedDek []byte, privKey *rsa.PrivateKey) (dek []byte, err error) {
	dek, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, wrappedDek, nil)
	return dek, err
}

func encryptDataWithDEK(dek, data []byte) ([]byte, error) {
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	dekGcm, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, err
	}
	dekNonce := make([]byte, dekGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dekNonce); err != nil {
		return nil, err
	}
	return dekGcm.Seal(dekNonce, dekNonce, data, nil), nil
}
