package gojwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type jwtClient struct {
	JwtConfig
}

func NewJwt(conf JwtConfig) *jwtClient {
	return &jwtClient{
		conf,
	}
}

// check 签发基础信息核验
func (rec *jwtClient) check(params *IssueParams) (err error) {
	// 基础配置校验
	switch rec.JwtAlgo { // 签名算法校验
	case AlgoHS256:
		if len(rec.JwtSecret) < 32 {
			return errors.New("HS256 requires a key of more than 32 bits")
		}
	case AlgoES256:
		if rec.JwtPrivate == nil {
			return errors.New("key can't be null")
		}
	default:
		return errors.New("unsupported algo")
	}
	// 签发参数校验
	if params.Duration <= 0 || params.Subject == "" {
		return errors.New("issuer:params missing")
	}
	if params.UUID == "" && params.UserID == 0 {
		return errors.New("issuer:params missing")
	}
	return
}
func (rec *jwtClient) defaultParams(params *IssueParams) {
	if params.JwtID == "" {
		params.JwtID = strings.ToUpper(uuid.NewString())
	}
	if params.NotBefore.IsZero() {
		params.NotBefore = time.Now()
	}
	// if params.Issuer == "" {
	// 	params.Issuer = "jwt.iss"
	// }
}

// Publish 颁发token
func (rec *jwtClient) Publish(params *IssueParams) (token, jwtID string, err error) {
	// 基础信息校验
	if err = rec.check(params); err != nil {
		return
	}
	// 默认值处理
	rec.defaultParams(params)
	// 构造JWT
	claims := TokenClaims{
		params.UserID,
		params.UUID,
		params.IssueIP,
		params.IssueClient,
		params.Ext,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(params.Duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(params.NotBefore),
			Issuer:    params.Issuer,
			Subject:   params.Subject,
			ID:        params.JwtID,
			Audience:  params.Audience,
		},
	}
	// 签发
	var method jwt.SigningMethod
	var secret interface{}
	if rec.JwtAlgo == AlgoES256 { // ES256签发
		method = jwt.SigningMethodES256
		secret = rec.JwtPrivate
	} else {
		method = jwt.SigningMethodHS256
		secret = []byte(rec.JwtSecret)
	}
	t := jwt.NewWithClaims(method,
		claims)
	if token, err = t.SignedString(secret); err != nil {
		return
	}
	return token, params.JwtID, err
}

func (rec *jwtClient) verifyNotBefore(token *jwt.Token) (err error) {
	var nbf *jwt.NumericDate
	if nbf, err = token.Claims.GetNotBefore(); err != nil || nbf == nil {
		return errors.New("token nbf is unverifiable")
	}
	if nbf.After(time.Now()) {
		return errors.New("token is not valid yet")
	}
	return
}
func (rec *jwtClient) verifyLifeCycle(token *jwt.Token, lifeCycle time.Duration) (err error) {
	var iss *jwt.NumericDate
	if iss, err = token.Claims.GetIssuedAt(); err != nil || iss == nil {
		return errors.New("token iss is unverifiable")
	}
	if iss.Add(lifeCycle).Before(time.Now()) {
		return fmt.Errorf("token is beyond the lifecycle(%v)", lifeCycle)
	}
	return
}
func (rec *jwtClient) validateOptions(params *ValidateParams) (opts []jwt.ParserOption) {
	opts = append(opts, jwt.WithSubject(params.Subject))
	if params.Audience != "" {
		opts = append(opts, jwt.WithAudience(params.Audience))
	}
	if params.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(params.Issuer))
	}
	if params.Leeway != 0 {
		opts = append(opts, jwt.WithLeeway(params.Leeway))
	}
	return
}

func (rec *jwtClient) tokenFormat(token string) (string, error) {
	if token == "" {
		return "", errors.New("token invalid")
	}
	tokenMap := strings.Split(token, "Bearer ")
	if len(tokenMap) != 2 {
		return "", errors.New("token bearer invalid")
	}
	return tokenMap[1], nil
}

func (rec *jwtClient) keyHandle(token *jwt.Token) (interface{}, error) {
	if rec.JwtAlgo == AlgoHS256 {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("signing algo unverifiable")
		}
		return []byte(rec.JwtSecret), nil
	}
	if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
		return nil, errors.New("signing algo unverifiable")
	}
	if rec.JwtPublic == nil {
		return nil, fmt.Errorf("public key is unverifiable")
	}
	return rec.JwtPublic, nil
}

// Validate 核验JWT
func (rec *jwtClient) Validate(params *ValidateParams) (res *TokenClaims, err error) {
	if params.Subject == "" {
		return nil, errors.New("subject invalid")
	}
	tokenStr, err := rec.tokenFormat(params.Token) // token格式化校验
	if err != nil {
		return
	}
	opts := rec.validateOptions(params) // 附加核验选项
	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return rec.keyHandle(token) // 签名算法核验、密钥处理
	}, opts...)
	if err != nil {
		return
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New("token invalid")
	}
	if params.Leeway != 0 && !params.LeewayNbf { // 定义了Leeway且Leeway不适用于nbf时，应当按标准重新检查nbf(底层jwt库已将Leeway应用到nbf检查)
		if err = rec.verifyNotBefore(token); err != nil {
			return nil, err
		}
	}
	if params.Leeway != 0 && params.LifeCycle != 0 { // 有Leeway时强制最长生命周期验证（拒绝无限续期）
		if err = rec.verifyLifeCycle(token, params.LifeCycle); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

// ParseRaw 解析原始token数据，只验签，不核验（外部token可能格式或核验规则与本库不兼容，导致Validate无法正常处理，验签解析原始数据map后自行处理）
func (rec *jwtClient) ParseRaw(tokenB string) (res jwt.MapClaims, err error) {
	tokenStr, err := rec.tokenFormat(tokenB) // token格式化校验
	if err != nil {
		return
	}
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return rec.keyHandle(token) // 签名算法核验、密钥处理
	})
	if err != nil {
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("token invalid")
	}
	return claims, nil
}
