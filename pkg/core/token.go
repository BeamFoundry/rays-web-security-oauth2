package core

import (
	"time"
)

// TokenType represents the OAuth 2.0 token type (e.g. Bearer)
type TokenType string

const (
	// TokenTypeBearer represents the RFC 6750 Bearer token type.
	TokenTypeBearer TokenType = "Bearer"
)

// OAuth2Token is the base interface for OAuth 2.0 tokens
type OAuth2Token interface {
	// GetTokenValue returns the raw string value of the token.
	GetTokenValue() string
	// GetIssuedAt returns the timestamp when the token was issued.
	GetIssuedAt() time.Time
	// GetExpiresAt returns the timestamp when the token expires.
	GetExpiresAt() time.Time
}

// OAuth2AccessToken represents an OAuth 2.0 Access Token
type OAuth2AccessToken struct {
	TokenValue string    `json:"access_token"`
	TokenType  TokenType `json:"token_type"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Scopes     []string  `json:"scopes"`
}

// New creates a new OAuth2AccessToken with the specified type, value, timestamps, and scopes.
func (this OAuth2AccessToken) New(tokenType TokenType, tokenValue string, issuedAt, expiresAt time.Time, scopes []string) *OAuth2AccessToken {
	this.TokenType = tokenType
	this.TokenValue = tokenValue
	this.IssuedAt = issuedAt
	this.ExpiresAt = expiresAt
	this.Scopes = scopes
	return &this
}

// NewOAuth2AccessToken creates a new OAuth2AccessToken.
func NewOAuth2AccessToken(tokenType TokenType, tokenValue string, issuedAt, expiresAt time.Time, scopes []string) *OAuth2AccessToken {
	return OAuth2AccessToken{}.New(tokenType, tokenValue, issuedAt, expiresAt, scopes)
}

// GetTokenValue returns the raw access token value.
func (this *OAuth2AccessToken) GetTokenValue() string {
	return this.TokenValue
}

// GetIssuedAt returns the time at which the access token was issued.
func (this *OAuth2AccessToken) GetIssuedAt() time.Time {
	return this.IssuedAt
}

// GetExpiresAt returns the expiration time of the access token.
func (this *OAuth2AccessToken) GetExpiresAt() time.Time {
	return this.ExpiresAt
}

// IsExpired reports whether the access token has expired relative to the current time.
func (this *OAuth2AccessToken) IsExpired() bool {
	if this.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(this.ExpiresAt)
}

// OAuth2RefreshToken represents an OAuth 2.0 Refresh Token
type OAuth2RefreshToken struct {
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	TokenValue  string    `json:"refresh_token"`
	Invalidated bool      `json:"invalidated,omitempty"`
}

// New creates a new OAuth2RefreshToken with the specified token value and timestamps.
func (this OAuth2RefreshToken) New(tokenValue string, issuedAt, expiresAt time.Time) *OAuth2RefreshToken {
	this.TokenValue = tokenValue
	this.IssuedAt = issuedAt
	this.ExpiresAt = expiresAt
	this.Invalidated = false
	return &this
}

// NewOAuth2RefreshToken creates a new OAuth2RefreshToken.
func NewOAuth2RefreshToken(tokenValue string, issuedAt, expiresAt time.Time) *OAuth2RefreshToken {
	return OAuth2RefreshToken{}.New(tokenValue, issuedAt, expiresAt)
}

// GetTokenValue returns the raw refresh token value.
func (this *OAuth2RefreshToken) GetTokenValue() string {
	return this.TokenValue
}

// GetIssuedAt returns the time at which the refresh token was issued.
func (this *OAuth2RefreshToken) GetIssuedAt() time.Time {
	return this.IssuedAt
}

// GetExpiresAt returns the expiration time of the refresh token.
func (this *OAuth2RefreshToken) GetExpiresAt() time.Time {
	return this.ExpiresAt
}
