package resourceserver

import (
	"encoding/gob"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// BearerTokenAuthenticationToken represents an unauthenticated bearer token
type BearerTokenAuthenticationToken struct {
	Token string `json:"token"`
	AbstractAuthenticationToken
}

var _ Authentication = &BearerTokenAuthenticationToken{}

func (this BearerTokenAuthenticationToken) New(token string) *BearerTokenAuthenticationToken {
	this.Token = token
	this.Principal = ""
	this.Authenticated = false
	return &this
}

func NewBearerTokenAuthenticationToken(token string) *BearerTokenAuthenticationToken {
	return BearerTokenAuthenticationToken{}.New(token)
}

func (this *BearerTokenAuthenticationToken) GetCredentials() any {
	return this.Token
}

// JwtAuthenticationToken represents an authenticated token verified from a JWT
type JwtAuthenticationToken struct {
	Jwt  *Jwt   `json:"jwt"`
	Name string `json:"name"`
	AbstractAuthenticationToken
}

var _ Authentication = &JwtAuthenticationToken{}

func (this JwtAuthenticationToken) New(
	token *Jwt,
	authorities []GrantedAuthority,
	name string,
) *JwtAuthenticationToken {
	this.Jwt = token
	this.Name = name
	this.Principal = token
	this.Authorities = authorities
	this.Authenticated = true
	return &this
}

func NewJwtAuthenticationToken(
	token *Jwt,
	authorities []GrantedAuthority,
	name string,
) *JwtAuthenticationToken {
	return JwtAuthenticationToken{}.New(token, authorities, name)
}

func (this *JwtAuthenticationToken) GetName() string {
	if this.Name != "" {
		return this.Name
	}
	if this.Jwt != nil {
		return this.Jwt.Subject()
	}
	return ""
}

func (this *JwtAuthenticationToken) GetCredentials() any {
	if this.Jwt != nil {
		return this.Jwt.TokenValue
	}
	return ""
}

func init() {
	gob.Register(&BearerTokenAuthenticationToken{})
	gob.Register(&JwtAuthenticationToken{})
}
