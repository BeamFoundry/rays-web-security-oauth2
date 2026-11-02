package core

import (
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2Error represents standard RFC 6749 OAuth 2.0 error responses
type OAuth2Error struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

const (
	OAuth2ErrorInvalidRequest          = "invalid_request"
	OAuth2ErrorUnauthorizedClient      = "unauthorized_client"
	OAuth2ErrorAccessDenied            = "access_denied"
	OAuth2ErrorUnsupportedResponseType = "unsupported_response_type"
	OAuth2ErrorInvalidScope            = "invalid_scope"
	OAuth2ErrorServerError             = "server_error"
	OAuth2ErrorTemporarilyUnavailable  = "temporarily_unavailable"
	OAuth2ErrorInvalidClient           = "invalid_client"
	OAuth2ErrorInvalidGrant            = "invalid_grant"
	OAuth2ErrorUnsupportedGrantType    = "unsupported_grant_type"
	OAuth2ErrorInvalidToken            = "invalid_token"
	OAuth2ErrorInsufficientScope       = "insufficient_scope"
)

// OAuth2AuthenticationException represents an authentication error during OAuth2 processing
type OAuth2AuthenticationException struct {
	authentication Authentication
	*DefaultError
	oauth2Error OAuth2Error
}

var _ AuthenticationException = &OAuth2AuthenticationException{}

func (this OAuth2AuthenticationException) New(oauth2Error OAuth2Error, authentication Authentication) *OAuth2AuthenticationException {
	msg := oauth2Error.ErrorCode
	if oauth2Error.ErrorDescription != "" {
		msg += ": " + oauth2Error.ErrorDescription
	}
	this.DefaultError = NewError("OAuth2AuthenticationException", msg)
	this.oauth2Error = oauth2Error
	this.authentication = authentication
	return &this
}

func NewOAuth2AuthenticationException(oauth2Error OAuth2Error, authentication Authentication) *OAuth2AuthenticationException {
	return OAuth2AuthenticationException{}.New(oauth2Error, authentication)
}

func (this *OAuth2AuthenticationException) OAuth2Error() OAuth2Error {
	return this.oauth2Error
}

func (this *OAuth2AuthenticationException) AuthenticationRequest() Authentication {
	return this.authentication
}
