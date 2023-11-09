package gojwt

import (
	"crypto/ecdsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const AlgoES256 = "ES256"
const AlgoHS256 = "HS256"

type JwtConfig struct {
	JwtAlgo    string            `dc:"* 指定JWT签名算法，支持 ES256(建议)，HS256(不建议)"`
	JwtPrivate *ecdsa.PrivateKey `dc:"*(根据算法二选一) jwt签名私钥证书，根据签名算法选择，ES256应传"`
	JwtPublic  *ecdsa.PublicKey  `dc:"*(根据算法二选一) jwt验签公钥证书，根据签名算法选择，ES256应传"`
	JwtSecret  string            `dc:"*(根据算法二选一) jwt签名密钥，根据签名算法选择，HS256应传不低于32位字符密钥加签"`
}

type TokenClaims struct {
	UID  int64  `json:"uid,omitempty"`  // int64类型用户编码
	UUID string `json:"uuid,omitempty"` // string类型UUID
	IP   string `json:"ip,omitempty"`   // 签发IP，用于辅助验证
	UA   string `json:"ua,omitempty"`   // 签发客户端SUM信息，用于辅助验证
	Ext  string `json:"ext,omitempty"`
	jwt.RegisteredClaims
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

type IssueParams struct {
	Subject   string        `json:"subject"`          // * jwt主题键，如：UserAuth 用户验证 , Access 临时权限验证等
	UID       int64         `json:"uid,omitempty"`    // int64类型用户编码 UID 或 UUID 二选一
	UUID      string        `json:"uuid,omitempty"`   // * string 类型 UUID 或 UID 二选一
	Duration  time.Duration `json:"duration"`         // * 授权时长
	Audience  []string      `json:"audience"`         // 可选，授权作用域列表，验证时可判断授权是否在颁发列表内
	NotBefore time.Time     `json:"notBefore"`        // 可选，启用时间
	Ext       string        `json:"ext,omitempty"`    // 可选，额外用户信息，例如邮箱、昵称等，不建议存储用户敏感数据，如存储敏感数据请进行加密。
	JwtID     string        `json:"jwtID,omitempty"`  // 可选，自定义 jti，不传使用随机uuid
	Issuer    string        `json:"issuer,omitempty"` // 可选，签发者标记（可用于分布式签发端标记等）
	IP        string        `json:"ip,omitempty"`     // 签发IP，用于辅助验证
	UA        string        `json:"ua,omitempty"`     // 签发客户端SUM信息，用于辅助验证
}
