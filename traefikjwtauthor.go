package traefikjwtauthor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/techidea8/codectl/infra/token"
)

// 不要设置为const
// 设置成cost 后初始化将无法覆盖
var (
	TokenParam    string = "Authorization"
	TokenPrefix   string = ""
	HeaderPrefix  string = "X-Turing-"
	DefaultSecret string = "turingdance@1232w3e4r"
)

// 系统会将这些东西传递到第三方
type Config struct {
	TokenParam   string   `json:"tokenParam,omitempty" toml:"tokenParam,omitempty" yaml:"tokenParam,omitempty"`
	TokenSecret  string   `json:"tokenSecret,omitempty" toml:"tokenSecret,omitempty" yaml:"tokenSecret,omitempty"`
	TokenPrefix  string   `json:"tokenPrefix,omitempty" toml:"tokenPrefix,omitempty" yaml:"tokenPrefix,omitempty"`
	HeaderPrefix string   `json:"headerPrefix,omitempty" toml:"headerPrefix,omitempty" yaml:"headerPrefix,omitempty"`
	WhiteList    []string `json:"whiteList,omitempty" toml:"whiteList,omitempty" yaml:"whiteList,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		WhiteList:    []string{},
		TokenSecret:  DefaultSecret,
		TokenParam:   TokenParam,
		HeaderPrefix: HeaderPrefix,
		TokenPrefix:  TokenPrefix,
	}
}

// RealIPOverWriter is a plugin that blocks incoming requests depending on their source IP.
type JwtAuthor struct {
	config   Config
	next     http.Handler
	name     string
	tokenmgr *token.TokenManager
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	//c, _ := json.Marshal(config)
	println("init" + name + " success ")
	return &JwtAuthor{
		config:   *config,
		next:     next,
		name:     name,
		tokenmgr: token.NewTokenManager(config.TokenSecret),
	}, nil
}

func (r *JwtAuthor) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	uri := req.RequestURI
	pass := false
	for _, v := range r.config.WhiteList {
		if strings.Contains(uri, v) {
			pass = true
			break
		}
	}
	msg := req.RequestURI + " not permited,please login "
	// 如果没有过,那么直接采用鉴权策略
	if !pass {
		tokenstr := req.Header.Get(r.config.TokenParam)
		tokenstr = strings.TrimPrefix(tokenstr, r.config.TokenPrefix)
		tokenMap, e1 := r.tokenmgr.ParseToken(tokenstr)
		if e1 != nil {
			msg = req.RequestURI + " 被拒绝,请先登录 "
			pass = false
		} else {
			pass = true
		}
		for key, value := range tokenMap {
			switch value := value.(type) {
			case int64:
			case int32:
			case int:
				req.Header.Add(key, fmt.Sprintf("%s-%d", r.config.HeaderPrefix, value))
			case float32:
			case float64:
				req.Header.Add(key, fmt.Sprintf("%s-%f", r.config.HeaderPrefix, value))
			case string:
				req.Header.Add(key, fmt.Sprintf("%s-%s", r.config.HeaderPrefix, value))
			}

		}
	}
	if pass {
		r.next.ServeHTTP(rw, req)
	} else {
		rw.WriteHeader(http.StatusForbidden)
		json.NewEncoder(rw).Encode(map[string]any{
			"code": 403,
			"msg":  msg,
		})
	}
}
