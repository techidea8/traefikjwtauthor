package token

import "encoding/json"

// iss: jwt签发者
// sub: jwt所面向的用户
// aud: 接收jwt的一方
// exp: jwt的过期时间，这个过期时间必须要大于签发时间
// nbf: 定义在什么时间之前，该jwt都是不可用的.
// iat: jwt的签发时间
// jti: jwt的唯一身份标识，主要用来作为一次性token。
const defaultISS string = "turing-microapp-server"
const defaultAUD string = "turing-microapp-client"
const (
	ClaimKeyIat string = "iat"
	ClaimKeyIss string = "iss"
	ClaimKeyAud string = "aud"
	ClaimKeyNbf string = "nbf"
	ClaimKeyExp string = "exp"
	ClaimKeySub string = "sub"
	ClaimKeyJti string = "jti"
)

type ClaimEntity struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

// 通过tokenMap 构建Ob'j'e'c't健权信息
func BuildFrom(jwtClaim map[string]interface{}, ptrobj interface{}) (claim *ClaimEntity, err error) {
	claim = &ClaimEntity{
		Iss: jwtClaim[ClaimKeyIss].(string),
		Sub: jwtClaim[ClaimKeySub].(string),
		Aud: jwtClaim[ClaimKeyAud].(string),
		Jti: jwtClaim[ClaimKeyJti].(string),
	}
	switch exp := jwtClaim[ClaimKeyExp].(type) {
	case float64:
		claim.Exp = int64(exp)
	case json.Number:
		claim.Exp, _ = exp.Int64()
	}
	switch nbf := jwtClaim[ClaimKeyNbf].(type) {
	case float64:
		claim.Nbf = int64(nbf)
	case json.Number:
		claim.Nbf, _ = nbf.Int64()
	}
	switch iat := jwtClaim[ClaimKeyIat].(type) {
	case float64:
		claim.Iat = int64(iat)
	case json.Number:
		claim.Iat, _ = iat.Int64()
	}
	bts, err := json.Marshal(jwtClaim)
	if err != nil {
		return claim, err
	}
	err = json.Unmarshal(bts, ptrobj)
	return claim, err
}
