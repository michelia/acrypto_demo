// @Author : 郭书广
// @Time   : Thu, 26 Aug 2021

// Package ecc ...
package ecc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenKey(t *testing.T) {
	a := assert.New(t)
	a.True(true)
	privatekey, publickey := genKey()
	privateKey, err := ReadPrivateKey("private.pem")
	a.NoError(err)
	a.Equal(privatekey, privateKey)
	publicKey, err := ReadPublicKey("public.pem")
	a.NoError(err)
	a.Equal(publickey, publicKey)
}
