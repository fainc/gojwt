package gojwt

import (
	"fmt"
	"testing"
	"time"
)

func TestIssuer_Publish(t *testing.T) {
	j := NewJwt(JwtConfig{JwtSecret: "12345678123456781234567812345678", JwtAlgo: AlgoHS256})
	publish, _, err := j.Publish(&IssueParams{
		Subject:  "Auth",
		Duration: 1 * time.Second,
		Audience: []string{"a", "b"},
		JwtID:    "",
		Issuer:   "SSO",
		PayloadClaims: PayloadClaims{
			UID: 1,
			Ext: map[string]interface{}{"name": "lin"},
			IP:  "127.0.0.1",
			UA:  "sum",
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(publish)
	raw, err := j.Validate(&ValidateParams{
		Subject:   "Auth",
		Token:     "Bearer " + publish,
		Audience:  "a",
		Issuer:    "",
		Leeway:    0,
		LeewayNbf: false,
		LifeCycle: 0,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(raw.UUID)
	fmt.Println(raw.UID)
	fmt.Println(raw.Ext)
}
