package service

import "crypto/rand"

type TokenGenerator interface {
	Generate(n uint) []byte
}

type CryptoTokenGenerator struct{}

func NewCryptoTokenGenerator() *CryptoTokenGenerator {
	return &CryptoTokenGenerator{}
}

func (c *CryptoTokenGenerator) Generate(n uint) []byte {
	token := make([]byte, n)
	_, err := rand.Read(token)
	if err != nil {
		panic("Error generating random token")
	}
	return token
}
