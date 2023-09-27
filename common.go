package gojwt

import (
	"github.com/golang-jwt/jwt/v5"
)

const AlgoES256 = "ES256"
const AlgoHS256 = "HS256"
const AlgoAES = "AES256"
const AlgoSM4 = "SM4"

type TokenClaims struct {
	UserID     string `json:"uid,omitempty"`
	Ext        string `json:"ext,omitempty"`
	CryptoAlgo string `json:"crypto,omitempty"`
	jwt.RegisteredClaims
}
