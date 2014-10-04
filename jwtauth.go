package jwtauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/zenazn/goji/web"
)

var (
	errUnauthorized = errors.New("unauthorized token")
)

type jwtAuth struct {
	signKey   []byte
	verifyKey []byte
	signer    jwt.SigningMethod
}

// verifyKey is only for RSA
func New(alg string, signKey []byte, verifyKey []byte) *jwtAuth {
	return &jwtAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    jwt.GetSigningMethod(alg),
	}
}

func (ja *jwtAuth) Handle(paramAliases ...string) func(http.Handler) http.Handler {
	f := func(h http.Handler) http.Handler {
		fn := func(c web.C, w http.ResponseWriter, r *http.Request) {
			if c.Env == nil {
				c.Env = make(map[string]interface{})
			}

			var tokenStr string
			var err error

			// Get token from query params
			tokenStr = r.URL.Query().Get("jwt")

			// Get token from other query param aliases
			if tokenStr == "" && paramAliases != nil && len(paramAliases) > 0 {
				for _, p := range paramAliases {
					tokenStr = r.URL.Query().Get(p)
					if tokenStr != "" {
						break
					}
				}
			}

			// Get token from authorization header
			if tokenStr == "" {
				bearer := r.Header.Get("Authorization")
				if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
					tokenStr = bearer[7:]
				}
			}

			// Get token from cookie
			if tokenStr == "" {
				cookie, err := r.Cookie("jwt")
				if err == nil {
					tokenStr = cookie.Value
				}
			}

			// Token is required, cya
			if tokenStr == "" {
				err = errUnauthorized
			}

			// Verify the token
			token, err := ja.Decode(tokenStr)
			if err != nil || !token.Valid {
				http.Error(w, errUnauthorized.Error(), 401)
				return
			}

			// Token is valid! save it in the context
			c.Env["token"] = token
			h.ServeHTTP(w, r)
		}
		return web.HandlerFunc(fn)
	}
	return f
}

func (ja *jwtAuth) Handler(h http.Handler) http.Handler {
	return ja.Handle("")(h)
}

func (ja *jwtAuth) Encode(claims map[string]interface{}) (tokenString string, err error) {
	return jwt.New(ja.signer).SignedString(ja.signKey)
}

func (ja *jwtAuth) Decode(tokenString string) (token *jwt.Token, err error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if ja.verifyKey != nil && len(ja.verifyKey) > 0 {
			return ja.verifyKey, nil
		} else {
			return ja.signKey, nil
		}
	})
}
