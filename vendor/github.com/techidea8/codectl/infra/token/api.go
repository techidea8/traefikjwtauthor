package token

import (
	"errors"
	"net/http"
	"strings"
)

func GenerateToken(values map[string]interface{}) (string, error) {
	return DefaultTokenManager.GenerateToken(values)
}

// 从request 中获取头
func GetAuthorizationFromRequest(req *http.Request) string {
	token := req.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, " ")
	return token
}
func ParseToken(in interface{}) (result map[string]interface{}, err error) {
	if token, ok := in.(string); ok {
		return DefaultTokenManager.ParseToken(token)
	} else if req, ok := in.(*http.Request); ok {
		token := GetAuthorizationFromRequest(req)
		return DefaultTokenManager.ParseToken(token)
	} else {
		return nil, errors.New("不支持的数据类型")
	}
}
