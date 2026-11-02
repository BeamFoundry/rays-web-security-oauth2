package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	. "github.com/BeamFoundry/rays/pkg/lang"
)

// Jwt represents a validated and decoded JSON Web Token (RFC 7519)
type Jwt struct {
	IssuedAt   time.Time      `json:"issued_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Headers    map[string]any `json:"headers"`
	Claims     map[string]any `json:"claims"`
	TokenValue string         `json:"token_value"`
}

func (this Jwt) New(tokenValue string, issuedAt, expiresAt time.Time, headers, claims map[string]any) *Jwt {
	this.TokenValue = tokenValue
	this.IssuedAt = issuedAt
	this.ExpiresAt = expiresAt
	this.Headers = headers
	this.Claims = claims
	return &this
}

func NewJwt(tokenValue string, issuedAt, expiresAt time.Time, headers, claims map[string]any) *Jwt {
	return Jwt{}.New(tokenValue, issuedAt, expiresAt, headers, claims)
}

func (this *Jwt) Subject() string {
	if s, ok := this.Claims["sub"].(string); ok {
		return s
	}
	return ""
}

func (this *Jwt) Issuer() string {
	if s, ok := this.Claims["iss"].(string); ok {
		return s
	}
	return ""
}

func (this *Jwt) Audience() []string {
	if aud, ok := this.Claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			return []string{v}
		case []string:
			return v
		case []any:
			var res []string
			for _, item := range v {
				if s, ok := item.(string); ok {
					res = append(res, s)
				}
			}
			return res
		}
	}
	return nil
}

func (this *Jwt) KeyID() string {
	if kid, ok := this.Headers["kid"].(string); ok {
		return kid
	}
	return ""
}

// JwtDecoder decodes and verifies a JWT token string
type JwtDecoder interface {
	Decode(token string) (*Jwt, Error)
}

// JwtClaimsSet represents claims used to encode a new token
type JwtClaimsSet struct {
	ExpiresAt time.Time      `json:"exp"`
	NotBefore time.Time      `json:"nbf"`
	IssuedAt  time.Time      `json:"iat"`
	Claims    map[string]any `json:"-"`
	Issuer    string         `json:"iss,omitempty"`
	Subject   string         `json:"sub,omitempty"`
	JWTID     string         `json:"jti,omitempty"`
	Audience  []string       `json:"aud,omitempty"`
}

func (this JwtClaimsSet) New() *JwtClaimsSet {
	this.Claims = make(map[string]any)
	return &this
}

func NewJwtClaimsSet() *JwtClaimsSet {
	return JwtClaimsSet{}.New()
}

// JwtEncoderParameters holds headers and claims for token generation
type JwtEncoderParameters struct {
	Headers   map[string]any
	ClaimsSet *JwtClaimsSet
}

// JwtEncoder signs and encodes a JWT
type JwtEncoder interface {
	Encode(parameters *JwtEncoderParameters) (*Jwt, Error)
}

// ParseUnverified parses a raw JWT into headers and claims without signature verification
func ParseUnverified(token string) (headers, claims map[string]any, err Error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, NewError("InvalidJwtFormatError", fmt.Sprintf("invalid jwt format: expected 3 parts, got %d", len(parts)))
	}

	headerBytes, b64Err := base64.RawURLEncoding.DecodeString(parts[0])
	if b64Err != nil {
		return nil, nil, NewError("InvalidHeaderError", fmt.Sprintf("invalid header base64: %s", b64Err))
	}

	claimBytes, b64Err := base64.RawURLEncoding.DecodeString(parts[1])
	if b64Err != nil {
		return nil, nil, NewError("InvalidClaimsError", fmt.Sprintf("invalid claims base64: %s", b64Err))
	}

	headers = make(map[string]any)
	if jsonErr := json.Unmarshal(headerBytes, &headers); jsonErr != nil {
		return nil, nil, NewError("InvalidHeaderError", fmt.Sprintf("invalid header json: %s", jsonErr))
	}

	claims = make(map[string]any)
	if jsonErr := json.Unmarshal(claimBytes, &claims); jsonErr != nil {
		return nil, nil, NewError("InvalidClaimsError", fmt.Sprintf("invalid claims json: %s", jsonErr))
	}

	return headers, claims, nil
}
