package server

import (
	"crypto/rand"
	"encoding/base64"
	"slices"
	"strings"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2TokenGenerator generates access and refresh tokens
type OAuth2TokenGenerator interface {
	// Generate issues a new OAuth2AccessToken and optional OAuth2RefreshToken for the given authorization and client.
	Generate(authorization *OAuth2Authorization, client *RegisteredClient) (*OAuth2AccessToken, *OAuth2RefreshToken, Error)
}

// JwtOAuth2TokenGenerator generates signed JWT access tokens
type JwtOAuth2TokenGenerator struct {
	jwtEncoder JwtEncoder
	issuer     string
}

// New creates a new JwtOAuth2TokenGenerator with the given JwtEncoder and issuer identifier.
func (this JwtOAuth2TokenGenerator) New(encoder JwtEncoder, issuer string) *JwtOAuth2TokenGenerator {
	this.jwtEncoder = encoder
	this.issuer = issuer
	return &this
}

// NewJwtOAuth2TokenGenerator creates a new JwtOAuth2TokenGenerator.
func NewJwtOAuth2TokenGenerator(encoder JwtEncoder, issuer string) *JwtOAuth2TokenGenerator {
	return JwtOAuth2TokenGenerator{}.New(encoder, issuer)
}

// Generate creates a signed JWT access token and, if the client supports refresh_token, a cryptographically random refresh token.
func (this *JwtOAuth2TokenGenerator) Generate(authorization *OAuth2Authorization, client *RegisteredClient) (*OAuth2AccessToken, *OAuth2RefreshToken, Error) {
	now := time.Now()

	accessTTL := client.AccessTokenTimeToLive
	if accessTTL <= 0 {
		accessTTL = 1 * time.Hour
	}
	accessExpiresAt := now.Add(accessTTL)

	// Build JWT Claims Set per RFC 9068
	claimsSet := JwtClaimsSet{}.New()
	claimsSet.Issuer = this.issuer
	claimsSet.Subject = authorization.PrincipalName
	claimsSet.Audience = []string{client.ClientID}
	claimsSet.IssuedAt = now
	claimsSet.ExpiresAt = accessExpiresAt
	jtiBytes := make([]byte, 16)
	Try(func() {
		_, randErr := rand.Read(jtiBytes)
		RaiseNilErr(randErr)
	}).LogError()
	claimsSet.JWTID = "jti-" + base64.RawURLEncoding.EncodeToString(jtiBytes)
	if len(authorization.AuthorizedScopes) > 0 {
		claimsSet.Claims["scope"] = strings.Join(authorization.AuthorizedScopes, " ")
	}
	claimsSet.Claims["client_id"] = client.ClientID

	encodedJwt, err := this.jwtEncoder.Encode(&JwtEncoderParameters{
		ClaimsSet: claimsSet,
	})
	if err != nil {
		return nil, nil, err
	}

	accessToken := OAuth2AccessToken{}.New(
		TokenTypeBearer,
		encodedJwt.TokenValue,
		now,
		accessExpiresAt,
		authorization.AuthorizedScopes,
	)

	var refreshToken *OAuth2RefreshToken
	hasRefreshTokenGrant := slices.Contains(client.AuthorizationGrantTypes, GrantTypeRefreshToken)

	if hasRefreshTokenGrant {
		refreshTTL := client.RefreshTokenTimeToLive
		if refreshTTL <= 0 {
			refreshTTL = 30 * 24 * time.Hour // 30 days
		}
		refreshExpiresAt := now.Add(refreshTTL)

		refBytes := make([]byte, 32)
		Try(func() {
			_, randErr := rand.Read(refBytes)
			RaiseNilErr(randErr)
		}).LogError()
		refVal := base64.RawURLEncoding.EncodeToString(refBytes)

		refreshToken = OAuth2RefreshToken{}.New(refVal, now, refreshExpiresAt)
	}

	return accessToken, refreshToken, nil
}
