package resourceserver

import (
	"strings"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// BearerTokenResolver extracts the bearer token from the incoming request
type BearerTokenResolver interface {
	// Resolve extracts and returns the bearer token string from the request, or an empty string if none is present.
	Resolve(handler SecurityHandler) string
}

// DefaultBearerTokenResolver resolves tokens from the Authorization header
type DefaultBearerTokenResolver struct {
	allowFormEncodedBodyParameter bool
	allowURIQueryParameter        bool
}

// New creates a new DefaultBearerTokenResolver that extracts tokens from the Authorization header by default.
func (this DefaultBearerTokenResolver) New() *DefaultBearerTokenResolver {
	return &this
}

// NewDefaultBearerTokenResolver creates a new DefaultBearerTokenResolver.
func NewDefaultBearerTokenResolver() *DefaultBearerTokenResolver {
	return DefaultBearerTokenResolver{}.New()
}

// WithAllowURIQueryParameter enables or disables resolving the bearer token from the "access_token" URI query parameter.
func (this *DefaultBearerTokenResolver) WithAllowURIQueryParameter(allow bool) *DefaultBearerTokenResolver {
	this.allowURIQueryParameter = allow
	return this
}

// WithAllowFormEncodedBodyParameter enables or disables resolving the bearer token from the "access_token" form parameter.
func (this *DefaultBearerTokenResolver) WithAllowFormEncodedBodyParameter(allow bool) *DefaultBearerTokenResolver {
	this.allowFormEncodedBodyParameter = allow
	return this
}

// Resolve extracts the bearer token from the Authorization header, or optionally from form or query parameters.
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
