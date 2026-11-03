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
	// OAuth2ErrorInvalidRequest indicates the request is missing a required parameter or is otherwise malformed.
	OAuth2ErrorInvalidRequest = "invalid_request"
	// OAuth2ErrorUnauthorizedClient indicates the client is not authorized to request an authorization code or access token using this method.
	OAuth2ErrorUnauthorizedClient = "unauthorized_client"
	// OAuth2ErrorAccessDenied indicates the resource owner or authorization server denied the request.
	OAuth2ErrorAccessDenied = "access_denied"
	// OAuth2ErrorUnsupportedResponseType indicates the authorization server does not support obtaining an authorization code using this method.
	OAuth2ErrorUnsupportedResponseType = "unsupported_response_type"
	// OAuth2ErrorInvalidScope indicates the requested scope is invalid, unknown, or malformed.
	OAuth2ErrorInvalidScope = "invalid_scope"
	// OAuth2ErrorServerError indicates the authorization server encountered an unexpected condition.
	OAuth2ErrorServerError = "server_error"
	// OAuth2ErrorTemporarilyUnavailable indicates the authorization server is currently unable to handle the request.
	OAuth2ErrorTemporarilyUnavailable = "temporarily_unavailable"
	// OAuth2ErrorInvalidClient indicates client authentication failed.
	OAuth2ErrorInvalidClient = "invalid_client"
	// OAuth2ErrorInvalidGrant indicates the provided authorization grant or refresh token is invalid, expired, or revoked.
	OAuth2ErrorInvalidGrant = "invalid_grant"
	// OAuth2ErrorUnsupportedGrantType indicates the authorization grant type is not supported by the authorization server.
	OAuth2ErrorUnsupportedGrantType = "unsupported_grant_type"
	// OAuth2ErrorInvalidToken indicates the access token provided is expired, revoked, malformed, or invalid.
	OAuth2ErrorInvalidToken = "invalid_token"
	// OAuth2ErrorInsufficientScope indicates the request requires higher privileges than provided by the access token.
	OAuth2ErrorInsufficientScope = "insufficient_scope"
)

// OAuth2AuthenticationException represents an authentication error during OAuth2 processing
type OAuth2AuthenticationException struct {
	authentication Authentication
	*DefaultError
	oauth2Error OAuth2Error
}

var _ AuthenticationException = &OAuth2AuthenticationException{}

// New creates a new OAuth2AuthenticationException wrapping the given OAuth2Error and Authentication request.
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

// NewOAuth2AuthenticationException creates a new OAuth2AuthenticationException.
func NewOAuth2AuthenticationException(oauth2Error OAuth2Error, authentication Authentication) *OAuth2AuthenticationException {
	return OAuth2AuthenticationException{}.New(oauth2Error, authentication)
}

// OAuth2Error returns the underlying RFC 6749 OAuth2Error details.
func (this *OAuth2AuthenticationException) OAuth2Error() OAuth2Error {
	return this.oauth2Error
}

// AuthenticationRequest returns the Authentication request that was being processed when the error occurred.
func (this *OAuth2AuthenticationException) AuthenticationRequest() Authentication {
	return this.authentication
}
