package token

import (
	"fmt"
	"time"
)

// iss: jwt签发者
// sub: jwt所面向的用户
// aud: 接收jwt的一方
// exp: jwt的过期时间，这个过期时间必须要大于签发时间
// nbf: 定义在什么时间之前，该jwt都是不可用的.
// iat: jwt的签发时间
// jti: jwt的唯一身份标识，主要用来作为一次性token。
type Option func(map[string]interface{})

func WithISS(iss string) Option {
	return func(m map[string]interface{}) {
		m[ClaimKeyIss] = iss
	}
}

// 受众类型
func WithSUB(sub string) Option {
	return func(m map[string]interface{}) {
		m[ClaimKeySub] = sub
	}
}

// JWT 唯一ID
func WithJTI(jti interface{}) Option {
	return func(m map[string]interface{}) {
		switch jti := jti.(type) {
		case int64:
		case int32:
		case int16:
		case int8:
		case uint:
		case uint32:
		case uint64:
		case uint16:
		case uint8:
		case float32:
		case float64:
			m[ClaimKeyJti] = fmt.Sprintf("%s", int64(jti))
		case string:
			m[ClaimKeyJti] = jti
		default:
			m[ClaimKeyJti] = jti
		}
	}
}

// 经过多久过期
func WithEXP(d time.Duration) Option {
	return func(m map[string]interface{}) {
		m[ClaimKeyExp] = time.Now().Add(d).Unix()
		m[ClaimKeyIat] = time.Now().Unix()
	}
}

// 在unixAt 后过期
func WithEXPAT(unixAt int64) Option {
	return func(m map[string]interface{}) {
		m[ClaimKeyExp] = unixAt
	}
}

// 在unixAt 前有效
func WithNBF(unixAt int64) Option {
	return func(m map[string]interface{}) {
		m[ClaimKeyNbf] = unixAt
		m[ClaimKeyIat] = time.Now().Unix()
	}
}
