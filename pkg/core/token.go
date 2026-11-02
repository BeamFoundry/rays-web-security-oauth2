package core

import (
	"time"
)

// TokenType represents the OAuth 2.0 token type (e.g. Bearer)
type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
)

// OAuth2Token is the base interface for OAuth 2.0 tokens
type OAuth2Token interface {
	GetTokenValue() string
	GetIssuedAt() time.Time
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

func (this OAuth2AccessToken) New(tokenType TokenType, tokenValue string, issuedAt, expiresAt time.Time, scopes []string) *OAuth2AccessToken {
	this.TokenType = tokenType
	this.TokenValue = tokenValue
	this.IssuedAt = issuedAt
	this.ExpiresAt = expiresAt
	this.Scopes = scopes
	return &this
}

func NewOAuth2AccessToken(tokenType TokenType, tokenValue string, issuedAt, expiresAt time.Time, scopes []string) *OAuth2AccessToken {
	return OAuth2AccessToken{}.New(tokenType, tokenValue, issuedAt, expiresAt, scopes)
}

func (this *OAuth2AccessToken) GetTokenValue() string {
	return this.TokenValue
}

func (this *OAuth2AccessToken) GetIssuedAt() time.Time {
	return this.IssuedAt
}

func (this *OAuth2AccessToken) GetExpiresAt() time.Time {
	return this.ExpiresAt
}

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

func (this OAuth2RefreshToken) New(tokenValue string, issuedAt, expiresAt time.Time) *OAuth2RefreshToken {
	this.TokenValue = tokenValue
	this.IssuedAt = issuedAt
	this.ExpiresAt = expiresAt
	this.Invalidated = false
	return &this
}

func NewOAuth2RefreshToken(tokenValue string, issuedAt, expiresAt time.Time) *OAuth2RefreshToken {
	return OAuth2RefreshToken{}.New(tokenValue, issuedAt, expiresAt)
}

func (this *OAuth2RefreshToken) GetTokenValue() string {
	return this.TokenValue
}

func (this *OAuth2RefreshToken) GetIssuedAt() time.Time {
	return this.IssuedAt
}

func (this *OAuth2RefreshToken) GetExpiresAt() time.Time {
	return this.ExpiresAt
}
