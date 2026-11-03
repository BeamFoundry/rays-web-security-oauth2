package resourceserver

import (
	"strings"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// JwtAuthenticationConverter converts a decoded JWT into an authenticated Authentication
type JwtAuthenticationConverter interface {
	// Convert transforms a validated Jwt into an authenticated JwtAuthenticationToken.
	Convert(token *Jwt) (*JwtAuthenticationToken, Error)
}

// DefaultJwtAuthenticationConverter is the default implementation of JwtAuthenticationConverter
type DefaultJwtAuthenticationConverter struct {
	principalClaimName string
	authorityPrefix    string
	authoritiesClaims  []string
}

// New creates a new DefaultJwtAuthenticationConverter with default principal claim ("sub"), authority prefix ("SCOPE_"), and authority claim paths.
func (this DefaultJwtAuthenticationConverter) New() *DefaultJwtAuthenticationConverter {
	this.principalClaimName = defaultPrincipalClaimName
	this.authorityPrefix = defaultAuthorityPrefix
	this.authoritiesClaims = []string{claimScope, claimScp, "authorities", "roles", "realm_access.roles"}
	return &this
}

// NewDefaultJwtAuthenticationConverter creates a new DefaultJwtAuthenticationConverter.
func NewDefaultJwtAuthenticationConverter() *DefaultJwtAuthenticationConverter {
	return DefaultJwtAuthenticationConverter{}.New()
}

// WithPrincipalClaimName sets the JWT claim name used to extract the principal name.
func (this *DefaultJwtAuthenticationConverter) WithPrincipalClaimName(name string) *DefaultJwtAuthenticationConverter {
	this.principalClaimName = name
	return this
}

// WithAuthorityPrefix sets the prefix prepended to extracted authorities.
func (this *DefaultJwtAuthenticationConverter) WithAuthorityPrefix(prefix string) *DefaultJwtAuthenticationConverter {
	this.authorityPrefix = prefix
	return this
}

// WithAuthoritiesClaims sets the claim names or dot-separated claim paths inspected to extract granted authorities.
func (this *DefaultJwtAuthenticationConverter) WithAuthoritiesClaims(claims ...string) *DefaultJwtAuthenticationConverter {
	this.authoritiesClaims = claims
	return this
}

// getClaimValue retrieves a top-level or dot-separated nested claim value from a claims map.
func getClaimValue(claims map[string]any, path string) (any, bool) {
	if val, ok := claims[path]; ok {
		return val, true
	}
	if strings.Contains(path, ".") {
		parts := strings.Split(path, ".")
		var current any = claims
		for _, part := range parts {
			m, ok := current.(map[string]any)
			if !ok {
				return nil, false
			}
			current, ok = m[part]
			if !ok {
				return nil, false
			}
		}
		return current, true
	}
	return nil, false
}

// Convert extracts granted authorities and the principal name from the given Jwt and returns an authenticated JwtAuthenticationToken.
func (this *DefaultJwtAuthenticationConverter) Convert(token *Jwt) (*JwtAuthenticationToken, Error) {
	authorities := make([]GrantedAuthority, 0)

	addAuth := func(sourceClaim, s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if sourceClaim == claimScope || sourceClaim == claimScp {
			if this.authorityPrefix == "" {
				authorities = append(authorities, Authority(s))
			} else {
				authorities = append(authorities, Authority(this.authorityPrefix+s))
			}
			return
		}
		if strings.HasPrefix(s, "ROLE_") || strings.HasPrefix(s, "SCOPE_") || this.authorityPrefix == "" {
			authorities = append(authorities, Authority(s))
		} else {
			authorities = append(authorities, Authority(this.authorityPrefix+s))
		}
	}

	for _, claimKey := range this.authoritiesClaims {
		if val, ok := getClaimValue(token.Claims, claimKey); ok {
			switch v := val.(type) {
			case string:
				for part := range strings.SplitSeq(v, " ") {
					addAuth(claimKey, part)
				}
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok {
						addAuth(claimKey, s)
					}
				}
			case []string:
				for _, s := range v {
					addAuth(claimKey, s)
				}
			default:
			}
		}
	}

	principalName := token.Subject()
	if this.principalClaimName != defaultPrincipalClaimName {
		if customName, ok := token.Claims[this.principalClaimName].(string); ok && customName != "" {
			principalName = customName
		}
	}

	return JwtAuthenticationToken{}.New(token, authorities, principalName), nil
}
