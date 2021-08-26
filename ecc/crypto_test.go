// @Author : 郭书广
// @Time   : Thu, 26 Aug 2021

// Package ecc ...
package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSigningAndVerification(t *testing.T) {
	a := assert.New(t)
	a.True(true)

	// elliptic.P256 是一种椭圆曲线 elliptic.Curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a.NoError(err)

	// The public key is a part of the *rsa.PrivateKey struct
	publicKey := privateKey.PublicKey

	// msg := []byte("verifiable message1234")
	msg := []byte{0}

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	a.NoError(err)

	// msgHashSum := msgHash.Sum(nil)

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, msg)

	a.NoError(err)

	t.Log("signature: ", signature, len(signature))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, msg)
	a.NoError(err)
	t.Log(r.Text(36), s.Text(36))
	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	verify := ecdsa.VerifyASN1(&publicKey, msg, signature)
	a.True(verify)
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	t.Log("signature verified")
}
