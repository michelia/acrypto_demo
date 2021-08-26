// @Author : 郭书广
// @Time   : Thu, 26 Aug 2021

// Package ecc ...
package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// generate key
func genKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	// generate key
	// elliptic.P256 是一种椭圆曲线 elliptic.Curve
	privatekey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Cannot generate ecc key\n")
		os.Exit(1)
	}
	// Public Key
	publickey := &privatekey.PublicKey

	// dump private key to file
	privateKeyBytes, err := x509.MarshalECPrivateKey(privatekey)
	if err != nil {
		fmt.Printf("Cannot marshal ECC key\n")
		os.Exit(1)
	}
	privateKeyBlock := &pem.Block{
		Type:  "ECC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privatePem, err := os.Create("private.pem")
	if err != nil {
		fmt.Printf("error when create private.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		fmt.Printf("error when encode private pem: %s \n", err)
		os.Exit(1)
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey) // Format: PKCS1 or PKIX
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create("public.pem")
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error when encode public pem: %s \n", err)
		os.Exit(1)
	}
	return privatekey, publickey
}

// generate key
func ReadPrivateKey(filename string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("pem: block is nil")
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func ReadPublicKey(filename string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("pem: block is nil")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes) // Format: PKCS1 or PKIX
	if err != nil {
		return nil, err
	}
	return publicKey.(*ecdsa.PublicKey), nil
}
