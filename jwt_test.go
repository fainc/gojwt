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
		UID:      111,
		Duration: 1 * time.Second,
		Audience: nil,
		Ext:      nil,
		JwtID:    "",
		Issuer:   "",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(publish)
	raw, err := j.Validate(&ValidateParams{
		Subject:   "Auth",
		Token:     "Bearer " + publish,
		Audience:  "",
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
