package resourceserver

import (
	"strings"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OpaqueTokenAuthenticationConverter converts an introspected token and principal into an authenticated Authentication
type OpaqueTokenAuthenticationConverter interface {
	Convert(token string, principal OAuth2AuthenticatedPrincipal) (Authentication, Error)
}

// DefaultOpaqueTokenAuthenticationConverter is the default implementation of OpaqueTokenAuthenticationConverter
type DefaultOpaqueTokenAuthenticationConverter struct{}

var _ OpaqueTokenAuthenticationConverter = &DefaultOpaqueTokenAuthenticationConverter{}

func (this DefaultOpaqueTokenAuthenticationConverter) New() *DefaultOpaqueTokenAuthenticationConverter {
	return &this
}

func NewDefaultOpaqueTokenAuthenticationConverter() *DefaultOpaqueTokenAuthenticationConverter {
	return DefaultOpaqueTokenAuthenticationConverter{}.New()
}

func (this *DefaultOpaqueTokenAuthenticationConverter) Convert(token string, principal OAuth2AuthenticatedPrincipal) (Authentication, Error) {
	if principal == nil {
		return nil, NewError("IllegalArgumentException", "principal cannot be nil")
	}

	authorities := principal.GetAuthorities()
	attrs := principal.GetAttributes()

	var issuedAt, expiresAt time.Time
	if expVal, exists := attrs["exp"]; exists {
		if expSec, ok := parseIntegerTimestamp(expVal); ok {
			expiresAt = time.Unix(expSec, 0)
		}
	}
	if iatVal, exists := attrs["iat"]; exists {
		if iatSec, ok := parseIntegerTimestamp(iatVal); ok {
			issuedAt = time.Unix(iatSec, 0)
		}
	}

	var scopes []string
	if scopeVal, exists := attrs[claimScope]; exists {
		scopes = parseScopes(scopeVal)
	}
	if len(scopes) == 0 {
		if scpVal, scpExists := attrs[claimScp]; scpExists {
			scopes = parseScopes(scpVal)
		}
	}

	accessToken := NewOAuth2AccessToken(TokenTypeBearer, token, issuedAt, expiresAt, scopes)
	return NewBearerTokenAuthentication(principal, accessToken, authorities), nil
}

func parseScopes(val any) []string {
	var scopes []string
	switch v := val.(type) {
	case string:
		scopes = strings.Fields(v)
	case []string:
		for _, s := range v {
			for part := range strings.FieldsSeq(s) {
				scopes = append(scopes, part)
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				for part := range strings.FieldsSeq(s) {
					scopes = append(scopes, part)
				}
			}
		}
	default:
	}
	return scopes
}
