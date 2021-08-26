// @Author : 郭书广
// @Time   : Thu, 26 Aug 2021

// Package rsa ...
package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptionAndDecryption(t *testing.T) {
	a := assert.New(t)
	a.True(true)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	a.NoError(err)

	// The public key is a part of the *rsa.PrivateKey struct
	publicKey := privateKey.PublicKey

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte("super secret message"),
		nil)
	a.NoError(err)

	t.Log("encrypted bytes: ", encryptedBytes)

	// The first argument is an optional random data generator (the rand.Reader we used before)
	// we can set this value as nil
	// The OAEPOptions in the end signify that we encrypted the data using OAEP, and that we used
	// SHA256 to hash the input.
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	a.NoError(err)

	// We get back the original information in the form of bytes, which we
	// the cast to a string and print
	t.Log("decrypted message: ", string(decryptedBytes))
}

func TestSigningAndVerification(t *testing.T) {
	a := assert.New(t)
	a.True(true)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	a.NoError(err)

	// The public key is a part of the *rsa.PrivateKey struct
	publicKey := privateKey.PublicKey

	msg := []byte("verifiable message1234")

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	a.NoError(err)

	msgHashSum := msgHash.Sum(nil)

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	a.NoError(err)

	t.Log("signature: ", signature, len(signature))

	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	err = rsa.VerifyPSS(&publicKey, crypto.SHA256, msgHashSum, signature, nil)
	a.NoError(err)
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	t.Log("signature verified")
}
