package resourceserver

import (
	"strings"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// BearerTokenResolver extracts the bearer token from the incoming request
type BearerTokenResolver interface {
	Resolve(handler SecurityHandler) string
}

// DefaultBearerTokenResolver resolves tokens from the Authorization header
type DefaultBearerTokenResolver struct {
	allowFormEncodedBodyParameter bool
	allowURIQueryParameter        bool
}

func (this DefaultBearerTokenResolver) New() *DefaultBearerTokenResolver {
	return &this
}

func NewDefaultBearerTokenResolver() *DefaultBearerTokenResolver {
	return DefaultBearerTokenResolver{}.New()
}

func (this *DefaultBearerTokenResolver) WithAllowURIQueryParameter(allow bool) *DefaultBearerTokenResolver {
	this.allowURIQueryParameter = allow
	return this
}

func (this *DefaultBearerTokenResolver) WithAllowFormEncodedBodyParameter(allow bool) *DefaultBearerTokenResolver {
	this.allowFormEncodedBodyParameter = allow
	return this
}

func (this *DefaultBearerTokenResolver) Resolve(handler SecurityHandler) string {
	authHeader := handler.Header("Authorization")
	if authHeader != "" {
		if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
			return strings.TrimSpace(authHeader[7:])
		}
	}

	if this.allowFormEncodedBodyParameter {
		if token := handler.FormValue("access_token"); token != "" {
			return token
		}
	}

	if this.allowURIQueryParameter && handler.URL() != nil {
		q := handler.URL().Query()
		if token := q.Get("access_token"); token != "" {
			return token
		}
	}

	return ""
}
