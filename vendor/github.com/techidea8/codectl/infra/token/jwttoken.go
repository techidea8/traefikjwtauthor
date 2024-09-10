package token

import (
	"errors"
	"fmt"
	"time"

	"sync/atomic"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	defaultexpireduration time.Duration = 24 * 7 * time.Hour
	defaultSUB            string        = "user"
	currentTokenIndex                   = time.Now().Unix()
)

func UpdatEexpireDuration(d time.Duration) {
	defaultexpireduration = d
}

// GenToken 生成token
// iss: jwt签发者
// sub: jwt所面向的用户
// aud: 接收jwt的一方
// exp: jwt的过期时间，这个过期时间必须要大于签发时间
// nbf: 定义在什么时间之前，该jwt都是不可用的.
// iat: jwt的签发时间
// jti: jwt的唯一身份标识，主要用来作为一次性token。
func GenerateTokenWithSecret(values map[string]interface{}, secretKey string, options ...Option) (string, error) {
	atomic.AddInt64(&currentTokenIndex, 1)
	jti := fmt.Sprintf("token-%d", currentTokenIndex)
	claim := jwt.MapClaims{
		ClaimKeyIat: time.Now().Unix(),
		ClaimKeyIss: defaultISS,
		ClaimKeyAud: defaultAUD,
		ClaimKeyNbf: time.Now().Unix(),
		ClaimKeyExp: time.Now().Add(defaultexpireduration).Unix(),
		ClaimKeySub: defaultSUB,
		ClaimKeyJti: jti,
	}
	for _, option := range options {
		option(claim)
	}
	for key, value := range values {
		claim[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenStr, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

// VerfyToken 验证token
func ParseTokenWithSecret(token, secretKey string) (map[string]interface{}, error) {
	if token == "" {
		return nil, fmt.Errorf("鉴权信息为空")
	}
	tokenObj, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := tokenObj.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("鉴权信息解析错误")
	}
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return nil, errors.New("鉴权信息已过期")
	}
	if !tokenObj.Valid {
		return nil, errors.New("鉴权信息已失效")
	}
	return claims, nil
}
