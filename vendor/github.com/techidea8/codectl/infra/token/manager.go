package token

var DefaultTokenManager *TokenManager = &TokenManager{
	jwtSecret: "gateway@turingdance",
}

type TokenManager struct {
	jwtSecret string
}

func NewTokenManager(jwtSecret string) *TokenManager {
	return &TokenManager{
		jwtSecret: jwtSecret,
	}
}

// 注册
func (mgr *TokenManager) ParseToken(token string) (result map[string]interface{}, err error) {
	return ParseTokenWithSecret(token, mgr.jwtSecret)
}

func (mgr *TokenManager) GenerateToken(values map[string]interface{}) (string, error) {
	return GenerateTokenWithSecret(values, mgr.jwtSecret)
}
