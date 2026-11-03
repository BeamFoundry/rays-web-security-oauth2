package core

import (
	"encoding/gob"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// OAuth2AuthenticationToken represents an authenticated OAuth2 user
type OAuth2AuthenticationToken struct {
	AuthorizedClientRegistrationID string `json:"authorized_client_registration_id"`
	AbstractAuthenticationToken
}

var _ Authentication = &OAuth2AuthenticationToken{}

// New creates a new authenticated OAuth2AuthenticationToken for the given principal, authorities, and client registration ID.
func (this OAuth2AuthenticationToken) New(
	principal OAuth2User,
	authorities []GrantedAuthority,
	authorizedClientRegistrationID string,
) *OAuth2AuthenticationToken {
	this.AuthorizedClientRegistrationID = authorizedClientRegistrationID
	this.Principal = principal
	this.Authorities = authorities
	this.Authenticated = true
	return &this
}

// NewOAuth2AuthenticationToken creates a new authenticated OAuth2AuthenticationToken.
func NewOAuth2AuthenticationToken(
	principal OAuth2User,
	authorities []GrantedAuthority,
	authorizedClientRegistrationID string,
) *OAuth2AuthenticationToken {
	return OAuth2AuthenticationToken{}.New(principal, authorities, authorizedClientRegistrationID)
}

// GetCredentials returns the credentials associated with this token (always empty for an authenticated OAuth2 user).
func (this *OAuth2AuthenticationToken) GetCredentials() any {
	return ""
}

// GetName returns the name of the authenticated OAuth2User or Principal, or an empty string if unavailable.
func (this *OAuth2AuthenticationToken) GetName() string {
	if principal, ok := this.Principal.(OAuth2User); ok {
		return principal.GetName()
	}
	if p, ok := this.Principal.(Principal); ok {
		return p.GetName()
	}
	return ""
}

// OAuth2AuthorizationExchange holds the authorization request and response pair
type OAuth2AuthorizationExchange struct {
	AuthorizationRequest  *OAuth2AuthorizationRequest
	AuthorizationResponse *OAuth2AuthorizationResponse
}

// OAuth2AuthorizationRequest holds the initiated authorization request
type OAuth2AuthorizationRequest struct {
	AdditionalParams    map[string]string `json:"additional_params"`
	AuthorizationURI    string            `json:"authorization_uri"`
	ClientID            string            `json:"client_id"`
	RedirectURI         string            `json:"redirect_uri"`
	State               string            `json:"state"`
	CodeVerifier        string            `json:"code_verifier,omitempty"`
	CodeChallenge       string            `json:"code_challenge,omitempty"`
	CodeChallengeMethod string            `json:"code_challenge_method,omitempty"`
	Scopes              []string          `json:"scopes"`
}

// OAuth2AuthorizationResponse holds the callback parameters returned by the provider
type OAuth2AuthorizationResponse struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// OAuth2LoginAuthenticationToken is the unauthenticated token passed to AuthenticationManager
type OAuth2LoginAuthenticationToken struct {
	AuthorizationExchange OAuth2AuthorizationExchange
	ClientRegistration    *ClientRegistration
	AbstractAuthenticationToken
}

var _ Authentication = &OAuth2LoginAuthenticationToken{}

// New creates a new unauthenticated OAuth2LoginAuthenticationToken for the given client registration and authorization exchange.
func (this OAuth2LoginAuthenticationToken) New(
	clientReg *ClientRegistration,
	exchange OAuth2AuthorizationExchange,
) *OAuth2LoginAuthenticationToken {
	this.ClientRegistration = clientReg
	this.AuthorizationExchange = exchange
	this.Principal = clientReg.ClientID
	this.Authenticated = false
	return &this
}

// NewOAuth2LoginAuthenticationToken creates a new unauthenticated OAuth2LoginAuthenticationToken.
func NewOAuth2LoginAuthenticationToken(
	clientReg *ClientRegistration,
	exchange OAuth2AuthorizationExchange,
) *OAuth2LoginAuthenticationToken {
	return OAuth2LoginAuthenticationToken{}.New(clientReg, exchange)
}

// GetCredentials returns the authorization code from the authorization response, or an empty string if absent.
func (this *OAuth2LoginAuthenticationToken) GetCredentials() any {
	if this.AuthorizationExchange.AuthorizationResponse != nil {
		return this.AuthorizationExchange.AuthorizationResponse.Code
	}
	return ""
}

// init registers OAuth2 authentication tokens and default user implementations with encoding/gob.
func init() {
	gob.Register(&OAuth2AuthenticationToken{})
	gob.Register(&OAuth2LoginAuthenticationToken{})
	gob.Register(&DefaultOAuth2User{})
	gob.Register(&DefaultOidcUser{})
}
