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
		UserID:   111,
		Duration: 1 * time.Second,
		Audience: nil,
		Ext:      "",
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
	fmt.Println(raw.UserID)
	fmt.Println(raw)
}
