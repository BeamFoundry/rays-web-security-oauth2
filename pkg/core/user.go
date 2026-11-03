package core

import (
	"encoding/gob"
	"maps"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// OAuth2AuthenticatedPrincipal represents an authenticated OAuth2 principal
type OAuth2AuthenticatedPrincipal interface {
	Principal
	// GetAttributes returns the claims or attributes associated with the principal.
	GetAttributes() map[string]any
	// GetAuthorities returns the granted authorities assigned to the principal.
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

// New creates a new DefaultOAuth2User with the given authorities, attributes, and name attribute key (defaulting to "sub").
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

// NewDefaultOAuth2User creates a new DefaultOAuth2User.
func NewDefaultOAuth2User(
	authorities []GrantedAuthority,
	attributes map[string]any,
	nameAttributeKey string,
) *DefaultOAuth2User {
	return DefaultOAuth2User{}.New(authorities, attributes, nameAttributeKey)
}

// GetName returns the user's principal name looked up via NameAttributeKey in Attributes.
func (this *DefaultOAuth2User) GetName() string {
	if val, ok := this.Attributes[this.NameAttributeKey]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// GetAttributes returns the user's attributes map.
func (this *DefaultOAuth2User) GetAttributes() map[string]any {
	return this.Attributes
}

// GetAuthorities returns the authorities granted to the user.
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
	// GetIdToken returns the OpenID Connect ID Token associated with the user.
	GetIdToken() *OidcIdToken
	// GetUserInfo returns the OpenID Connect UserInfo claims associated with the user, if available.
	GetUserInfo() *OidcUserInfo
}

// DefaultOidcUser is the default implementation of OidcUser
type DefaultOidcUser struct {
	IdToken  *OidcIdToken  `json:"id_token"`
	UserInfo *OidcUserInfo `json:"user_info,omitempty"`
	DefaultOAuth2User
}

// New creates a new DefaultOidcUser merging claims from the ID token and optional UserInfo response.
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

// NewDefaultOidcUser creates a new DefaultOidcUser.
func NewDefaultOidcUser(
	authorities []GrantedAuthority,
	idToken *OidcIdToken,
	userInfo *OidcUserInfo,
	nameAttributeKey string,
) *DefaultOidcUser {
	return DefaultOidcUser{}.New(authorities, idToken, userInfo, nameAttributeKey)
}

// GetIdToken returns the user's OidcIdToken.
func (this *DefaultOidcUser) GetIdToken() *OidcIdToken {
	return this.IdToken
}

// GetUserInfo returns the user's OidcUserInfo.
func (this *DefaultOidcUser) GetUserInfo() *OidcUserInfo {
	return this.UserInfo
}

// DefaultOAuth2AuthenticatedPrincipal is the default implementation of OAuth2AuthenticatedPrincipal
type DefaultOAuth2AuthenticatedPrincipal struct {
	Name        string             `json:"name"`
	Attributes  map[string]any     `json:"attributes"`
	Authorities []GrantedAuthority `json:"authorities"`
}

var _ OAuth2AuthenticatedPrincipal = &DefaultOAuth2AuthenticatedPrincipal{}

// New creates a new DefaultOAuth2AuthenticatedPrincipal with the given principal name, attributes, and authorities.
func (this DefaultOAuth2AuthenticatedPrincipal) New(
	name string,
	attributes map[string]any,
	authorities []GrantedAuthority,
) *DefaultOAuth2AuthenticatedPrincipal {
	this.Name = name
	this.Attributes = attributes
	this.Authorities = authorities
	return &this
}

// NewDefaultOAuth2AuthenticatedPrincipal creates a new DefaultOAuth2AuthenticatedPrincipal.
func NewDefaultOAuth2AuthenticatedPrincipal(
	name string,
	attributes map[string]any,
	authorities []GrantedAuthority,
) *DefaultOAuth2AuthenticatedPrincipal {
	return DefaultOAuth2AuthenticatedPrincipal{}.New(name, attributes, authorities)
}

// GetName returns the authenticated principal's name.
func (this *DefaultOAuth2AuthenticatedPrincipal) GetName() string {
	return this.Name
}

// GetAttributes returns the attributes associated with the authenticated principal.
func (this *DefaultOAuth2AuthenticatedPrincipal) GetAttributes() map[string]any {
	return this.Attributes
}

// GetAuthorities returns the authorities granted to the authenticated principal.
func (this *DefaultOAuth2AuthenticatedPrincipal) GetAuthorities() []GrantedAuthority {
	return this.Authorities
}

// init registers DefaultOAuth2AuthenticatedPrincipal with encoding/gob.
func init() {
	gob.Register(&DefaultOAuth2AuthenticatedPrincipal{})
}
