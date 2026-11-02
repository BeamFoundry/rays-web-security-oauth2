package core

import (
	"maps"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// OAuth2AuthenticatedPrincipal represents an authenticated OAuth2 principal
type OAuth2AuthenticatedPrincipal interface {
	Principal
	GetAttributes() map[string]any
	GetAuthorities() []GrantedAuthority
}

// OAuth2User represents an authenticated OAuth 2.0 user
type OAuth2User interface {
	OAuth2AuthenticatedPrincipal
}

// DefaultOAuth2User is the default implementation of OAuth2User
type DefaultOAuth2User struct {
	Attributes       map[string]any     `json:"attributes"`
	NameAttributeKey string             `json:"name_attribute_key"`
	Authorities      []GrantedAuthority `json:"authorities"`
}

func (this DefaultOAuth2User) New(
	authorities []GrantedAuthority,
	attributes map[string]any,
	nameAttributeKey string,
) *DefaultOAuth2User {
	if nameAttributeKey == "" {
		nameAttributeKey = "sub"
	}
	this.Authorities = authorities
	this.Attributes = attributes
	this.NameAttributeKey = nameAttributeKey
	return &this
}

func NewDefaultOAuth2User(
	authorities []GrantedAuthority,
	attributes map[string]any,
	nameAttributeKey string,
) *DefaultOAuth2User {
	return DefaultOAuth2User{}.New(authorities, attributes, nameAttributeKey)
}

func (this *DefaultOAuth2User) GetName() string {
	if val, ok := this.Attributes[this.NameAttributeKey]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func (this *DefaultOAuth2User) GetAttributes() map[string]any {
	return this.Attributes
}

func (this *DefaultOAuth2User) GetAuthorities() []GrantedAuthority {
	return this.Authorities
}

// OidcIdToken represents an OpenID Connect ID Token
type OidcIdToken struct {
	Claims     map[string]any `json:"claims"`
	TokenValue string         `json:"token_value"`
}

// OidcUserInfo represents OpenID Connect UserInfo claims
type OidcUserInfo struct {
	Claims map[string]any `json:"claims"`
}

// OidcUser represents an authenticated OpenID Connect 1.0 user
type OidcUser interface {
	OAuth2User
	GetIdToken() *OidcIdToken
	GetUserInfo() *OidcUserInfo
}

// DefaultOidcUser is the default implementation of OidcUser
type DefaultOidcUser struct {
	IdToken  *OidcIdToken  `json:"id_token"`
	UserInfo *OidcUserInfo `json:"user_info,omitempty"`
	DefaultOAuth2User
}

func (this DefaultOidcUser) New(
	authorities []GrantedAuthority,
	idToken *OidcIdToken,
	userInfo *OidcUserInfo,
	nameAttributeKey string,
) *DefaultOidcUser {
	combined := make(map[string]any)
	if idToken != nil {
		maps.Copy(combined, idToken.Claims)
	}
	if userInfo != nil {
		maps.Copy(combined, userInfo.Claims)
		if idToken != nil {
			if sub, ok := idToken.Claims["sub"]; ok {
				combined["sub"] = sub
			}
		}
	}
	if nameAttributeKey == "" {
		nameAttributeKey = "sub"
	}

	this.DefaultOAuth2User = *DefaultOAuth2User{}.New(authorities, combined, nameAttributeKey)
	this.IdToken = idToken
	this.UserInfo = userInfo
	return &this
}

func NewDefaultOidcUser(
	authorities []GrantedAuthority,
	idToken *OidcIdToken,
	userInfo *OidcUserInfo,
	nameAttributeKey string,
) *DefaultOidcUser {
	return DefaultOidcUser{}.New(authorities, idToken, userInfo, nameAttributeKey)
}

func (this *DefaultOidcUser) GetIdToken() *OidcIdToken {
	return this.IdToken
}

func (this *DefaultOidcUser) GetUserInfo() *OidcUserInfo {
	return this.UserInfo
}
