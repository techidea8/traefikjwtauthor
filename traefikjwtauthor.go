package traefikjwtauthor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/techidea8/codectl/infra/token"
)

const (
	TokenParam    string = "Authorization"
	TokenPrefix   string = ""
	DefaultSecret string = "turingdance@1232w3e4r"
)

// 系统会将这些东西传递到第三方
type Config struct {
	Param        string   `json:"param,omitempty" toml:"param,omitempty" yaml:"param,omitempty"`
	Secrect      string   `json:"secret,omitempty" toml:"secret,omitempty" yaml:"secret,omitempty"`
	TokenPrefix  string   `json:"tokenPrefix,omitempty" toml:"tokenPrefix,omitempty" yaml:"tokenPrefix,omitempty"`
	HeaderPrefix string   `json:"headerPrefix,omitempty" toml:"headerPrefix,omitempty" yaml:"headerPrefix,omitempty"`
	WhiteList    []string `json:"whiteList,omitempty" toml:"whiteList,omitempty" yaml:"whiteList,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		WhiteList:    []string{},
		Secrect:      DefaultSecret,
		Param:        TokenParam,
		HeaderPrefix: "X-Turing-",
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
	println("init" + name + " success")
	return &JwtAuthor{
		config:   *config,
		next:     next,
		name:     name,
		tokenmgr: token.NewTokenManager(config.Secrect),
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
	// 如果没有过,那么直接采用鉴权策略
	if !pass {
		tokenstr := req.Header.Get(r.config.Param)
		tokenstr = strings.TrimPrefix(tokenstr, r.config.TokenPrefix)
		tokenMap, err := r.tokenmgr.ParseToken(tokenstr)
		if err != nil {
			pass = false
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
		json.NewEncoder(rw).Encode(map[string]any{
			"code": 403,
			"msg":  req.RequestURI + "not permited,please login",
		})
		rw.WriteHeader(http.StatusForbidden)
	}
}
