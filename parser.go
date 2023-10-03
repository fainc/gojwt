package gojwt

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fainc/go-crypto/crypto"
	"github.com/golang-jwt/jwt/v5"
)

type parser struct {
	conf *ParserConf
}

type ParserConf struct {
	JwtAlgo      string           `dc:"* 验证JWT签名算法，支持ES256(默认)和HS256"`
	JwtPublic    *ecdsa.PublicKey `dc:"*(根据算法二选一) jwt验签私钥证书，根据签名算法选择，ES256应传公钥验签"`
	JwtSecret    string           `dc:"*(根据算法二选一) jwt验签密钥，根据签名算法选择，HS256应传密钥验签"`
	CryptoSecret string           `dc:"可选，解密密钥（AES 256或SM4 128位密钥），不传则不进行内部解密，解密字段：UserID Ext（程序根据JWT声明加密类型判断解密算法，应指定对应算法密钥）"`
}

func Parser(conf ParserConf) *parser {
	return &parser{&conf}
}

type ValidateParams struct {
	Subject   string        `json:"subject" dc:"* jwt主题键"`
	Token     string        `json:"token" dc:"* 待验证token 需要Bearer标识符"`
	Audience  string        `json:"audience" dc:"可选，验证作用域，传入的值需在颁发时定义的授权作用域列表内，如传递则严格验证，不传递则不验证"`
	Issuer    string        `json:"issuer" dc:"可选，签发者标记（可用于分布式签发端标记等），如传递则严格验证，不传递则不验证"`
	Leeway    time.Duration `json:"leeway" dc:"可选，时间(exp、nbf)验证窗口期，一般用于token外部续期维护或跨系统时间同步宽容"`
	LeewayNbf bool          `json:"leewayNbf" dc:"可选，时间验证窗口期是否适用于nbf，Leeway用于token外部续期维护等情况时建议否，仅用于时间同步宽容时允许是"`
	LifeCycle time.Duration `json:"lifeCycle" dc:"可选，最长生命周期，常用于token有续期情况下(有Leeway)的强制最长有效期验证，防止token无限续期，未续期情况下一般依靠exp维护过期时间即可"`
}

func (rec *parser) verifyNotBefore(token *jwt.Token) (err error) {
	var nbf *jwt.NumericDate
	if nbf, err = token.Claims.GetNotBefore(); err != nil || nbf == nil {
		return errors.New("token nbf is unverifiable")
	}
	if nbf.After(time.Now()) {
		return errors.New("token is not valid yet")
	}
	return
}
func (rec *parser) verifyLifeCycle(token *jwt.Token, lifeCycle time.Duration) (err error) {
	var iss *jwt.NumericDate
	if iss, err = token.Claims.GetIssuedAt(); err != nil || iss == nil {
		return errors.New("token iss is unverifiable")
	}
	if iss.Add(lifeCycle).Before(time.Now()) {
		return fmt.Errorf("token is beyond the lifecycle(%v)", lifeCycle)
	}
	return
}
func (rec *parser) validateOptions(params ValidateParams) (opts []jwt.ParserOption) {
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
func (rec *parser) tokenFormat(token string) (string, error) {
	if token == "" {
		return "", errors.New("token invalid")
	}
	tokenMap := strings.Split(token, "Bearer ")
	if len(tokenMap) != 2 {
		return "", errors.New("token bearer invalid")
	}
	return tokenMap[1], nil
}
func (rec *parser) keyHandle(token *jwt.Token) (interface{}, error) {
	if rec.conf.JwtAlgo == AlgoHS256 {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("signing algo unverifiable")
		}
		return []byte(rec.conf.JwtSecret), nil
	}
	if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
		return nil, errors.New("signing algo unverifiable")
	}
	if rec.conf.JwtPublic == nil {
		return nil, fmt.Errorf("public key is unverifiable")
	}
	return rec.conf.JwtPublic, nil
}
func (rec *parser) decrypt(claims *TokenClaims) (err error) {
	if claims.CryptoAlgo != AlgoAES && claims.CryptoAlgo != AlgoSM4 {
		return errors.New("decrypted token: crypto algo unsupported")
	}
	if claims.UserID, err = crypto.EasyDecrypt(claims.CryptoAlgo, rec.conf.CryptoSecret, claims.UserID, false); err != nil {
		return errors.New("decrypted token: decrypt failed")
	}
	if claims.Ext, err = crypto.EasyDecrypt(claims.CryptoAlgo, rec.conf.CryptoSecret, claims.Ext, false); err != nil {
		return errors.New("decrypted token: decrypt failed")
	}
	return
}

// Validate 核验JWT
func (rec *parser) Validate(params ValidateParams) (res *TokenClaims, err error) {
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
	if claims.CryptoAlgo != "" {
		if rec.conf.CryptoSecret == "" {
			return nil, errors.New("secret invalid")
		}
		if err = rec.decrypt(claims); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

// ParseRaw 解析原始token数据，只验签，不核验（外部token可能格式或核验规则与本库不兼容，导致Validate无法正常处理，验签解析原始数据map后自行处理）
func (rec *parser) ParseRaw(tokenB string) (res jwt.MapClaims, err error) {
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
