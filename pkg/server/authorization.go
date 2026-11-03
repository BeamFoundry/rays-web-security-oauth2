package server

import (
	"sync"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2ParameterCode is the authorization code grant parameter name and token type
const OAuth2ParameterCode = "code"

// AuthorizationCode holds the issued authorization code details
type AuthorizationCode struct {
	Value               string    `json:"value"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	RedirectURI         string    `json:"redirect_uri"`
	RedirectURISupplied bool      `json:"redirect_uri_supplied"`
	Invalidated         bool      `json:"invalidated"`
}

// OAuth2Authorization represents an ongoing or completed OAuth 2.0 authorization
type OAuth2Authorization struct {
	AuthorizationCode  *AuthorizationCode  `json:"authorization_code,omitempty"`
	AccessToken        *OAuth2AccessToken  `json:"access_token,omitempty"`
	RefreshToken       *OAuth2RefreshToken `json:"refresh_token,omitempty"`
	ID                 string              `json:"id"`
	RegisteredClientID string              `json:"registered_client_id"`
	PrincipalName      string              `json:"principal_name"`
	AuthorizedScopes   []string            `json:"authorized_scopes"`
}

// OAuth2AuthorizationService manages authorization sessions
type OAuth2AuthorizationService interface {
	// Save persists a new or updated OAuth2Authorization.
	Save(authorization *OAuth2Authorization) Error
	// Remove deletes an OAuth2Authorization and all associated token indexes.
	Remove(authorization *OAuth2Authorization) Error
	// FindByID retrieves an OAuth2Authorization by its unique identifier.
	FindByID(id string) (*OAuth2Authorization, Error)
	// FindByToken retrieves an OAuth2Authorization by a token value and required tokenType selector ("code", "access_token", or "refresh_token").
	FindByToken(token, tokenType string) (*OAuth2Authorization, Error)
	// InvalidateAuthorizationCode atomically marks an authorization code as used and returns its OAuth2Authorization.
	InvalidateAuthorizationCode(code string) (*OAuth2Authorization, Error)
	// ConsumeRefreshToken atomically marks a refresh token as consumed and returns its OAuth2Authorization.
	ConsumeRefreshToken(token string) (*OAuth2Authorization, Error)
	// SaveTokens atomically updates the access and refresh tokens for an authorization while verifying the previous refresh token.
	// Passing an empty expectedOldRefreshToken disables the previous-refresh-token comparison; callers must not rely on the comparison when passing an empty value.
	SaveTokens(authID, expectedOldRefreshToken string, accessToken *OAuth2AccessToken, refreshToken *OAuth2RefreshToken) Error
}

// trackedTokens records the currently indexed token values for an authorization ID to clean up rotated tokens.
type trackedTokens struct {
	code         string
	accessToken  string
	refreshToken string
}

// InMemoryOAuth2AuthorizationService stores authorizations in memory.
// Repository operations are synchronized, but callers must synchronize concurrent access to or mutation of authorization objects shared with the repository.
type InMemoryOAuth2AuthorizationService struct {
	mu             *sync.RWMutex
	byID           map[string]*OAuth2Authorization
	byAuthCode     map[string]*OAuth2Authorization
	byAccessToken  map[string]*OAuth2Authorization
	byRefreshToken map[string]*OAuth2Authorization
	tracked        map[string]trackedTokens
}

// New creates a new InMemoryOAuth2AuthorizationService.
// Repository operations are synchronized, but callers must synchronize concurrent access to or mutation of authorization objects shared with the repository.
func (this InMemoryOAuth2AuthorizationService) New() *InMemoryOAuth2AuthorizationService {
	this.mu = &sync.RWMutex{}
	this.byID = make(map[string]*OAuth2Authorization)
	this.byAuthCode = make(map[string]*OAuth2Authorization)
	this.byAccessToken = make(map[string]*OAuth2Authorization)
	this.byRefreshToken = make(map[string]*OAuth2Authorization)
	this.tracked = make(map[string]trackedTokens)
	return &this
}

// NewInMemoryOAuth2AuthorizationService creates a new InMemoryOAuth2AuthorizationService.
// Repository operations are synchronized, but callers must synchronize concurrent access to or mutation of authorization objects shared with the repository.
func NewInMemoryOAuth2AuthorizationService() *InMemoryOAuth2AuthorizationService {
	return InMemoryOAuth2AuthorizationService{}.New()
}

// Save stores or updates an OAuth2Authorization and indexes its tokens in memory.
func (this *InMemoryOAuth2AuthorizationService) Save(auth *OAuth2Authorization) Error {
	this.mu.Lock()
	defer this.mu.Unlock()
	return this.saveLocked(auth)
}

// saveLocked persists the authorization and updates token lookup maps while holding the write lock.
func (this *InMemoryOAuth2AuthorizationService) saveLocked(auth *OAuth2Authorization) Error {
	prev := this.tracked[auth.ID]

	var newCode, newAccess, newRefresh string
	if auth.AuthorizationCode != nil {
		newCode = auth.AuthorizationCode.Value
	}
	if auth.AccessToken != nil {
		newAccess = auth.AccessToken.TokenValue
	}
	if auth.RefreshToken != nil {
		newRefresh = auth.RefreshToken.TokenValue
	}

	// Remove stale entries when saving rotated values, ensuring cleanup does not remove
	// an entry now owned by another authorization
	if prev.code != "" && prev.code != newCode {
		if existing, ok := this.byAuthCode[prev.code]; ok && existing.ID == auth.ID {
			delete(this.byAuthCode, prev.code)
		}
	}
	if prev.accessToken != "" && prev.accessToken != newAccess {
		if existing, ok := this.byAccessToken[prev.accessToken]; ok && existing.ID == auth.ID {
			delete(this.byAccessToken, prev.accessToken)
		}
	}
	if prev.refreshToken != "" && prev.refreshToken != newRefresh {
		if existing, ok := this.byRefreshToken[prev.refreshToken]; ok && existing.ID == auth.ID {
			delete(this.byRefreshToken, prev.refreshToken)
		}
	}

	this.byID[auth.ID] = auth
	if newCode != "" {
		this.byAuthCode[newCode] = auth
	}
	if newAccess != "" {
		this.byAccessToken[newAccess] = auth
	}
	if newRefresh != "" {
		this.byRefreshToken[newRefresh] = auth
	}

	this.tracked[auth.ID] = trackedTokens{
		code:         newCode,
		accessToken:  newAccess,
		refreshToken: newRefresh,
	}
	return nil
}

// Remove deletes an OAuth2Authorization and all of its associated token lookup entries from memory.
func (this *InMemoryOAuth2AuthorizationService) Remove(auth *OAuth2Authorization) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

	prev, hasTracked := this.tracked[auth.ID]
	if hasTracked {
		if prev.code != "" {
			if existing, ok := this.byAuthCode[prev.code]; ok && existing.ID == auth.ID {
				delete(this.byAuthCode, prev.code)
			}
		}
		if prev.accessToken != "" {
			if existing, ok := this.byAccessToken[prev.accessToken]; ok && existing.ID == auth.ID {
				delete(this.byAccessToken, prev.accessToken)
			}
		}
		if prev.refreshToken != "" {
			if existing, ok := this.byRefreshToken[prev.refreshToken]; ok && existing.ID == auth.ID {
				delete(this.byRefreshToken, prev.refreshToken)
			}
		}
		delete(this.tracked, auth.ID)
	}

	if auth.AuthorizationCode != nil && auth.AuthorizationCode.Value != "" {
		if existing, ok := this.byAuthCode[auth.AuthorizationCode.Value]; ok && existing.ID == auth.ID {
			delete(this.byAuthCode, auth.AuthorizationCode.Value)
		}
	}
	if auth.AccessToken != nil && auth.AccessToken.TokenValue != "" {
		if existing, ok := this.byAccessToken[auth.AccessToken.TokenValue]; ok && existing.ID == auth.ID {
			delete(this.byAccessToken, auth.AccessToken.TokenValue)
		}
	}
	if auth.RefreshToken != nil && auth.RefreshToken.TokenValue != "" {
		if existing, ok := this.byRefreshToken[auth.RefreshToken.TokenValue]; ok && existing.ID == auth.ID {
			delete(this.byRefreshToken, auth.RefreshToken.TokenValue)
		}
	}

	delete(this.byID, auth.ID)
	return nil
}

// InvalidateAuthorizationCode validates that an authorization code is active and marks it as invalidated for single use.
func (this *InMemoryOAuth2AuthorizationService) InvalidateAuthorizationCode(code string) (*OAuth2Authorization, Error) {
	this.mu.Lock()
	defer this.mu.Unlock()

	auth, ok := this.byAuthCode[code]
	if !ok || auth == nil || auth.AuthorizationCode == nil {
		return nil, NewError("InvalidGrantError", "Invalid or unknown authorization code")
	}

	if auth.AuthorizationCode.Invalidated || time.Now().After(auth.AuthorizationCode.ExpiresAt) {
		return nil, NewError("InvalidGrantError", "Authorization code has expired or was already used")
	}

	auth.AuthorizationCode.Invalidated = true
	return auth, nil
}

// ConsumeRefreshToken validates that a refresh token is active and marks it as invalidated for rotation.
func (this *InMemoryOAuth2AuthorizationService) ConsumeRefreshToken(token string) (*OAuth2Authorization, Error) {
	this.mu.Lock()
	defer this.mu.Unlock()

	auth, ok := this.byRefreshToken[token]
	if !ok || auth == nil || auth.RefreshToken == nil {
		return nil, NewError("InvalidGrantError", "Invalid or unknown refresh token")
	}

	if auth.RefreshToken.Invalidated || (!auth.RefreshToken.ExpiresAt.IsZero() && time.Now().After(auth.RefreshToken.ExpiresAt)) {
		return nil, NewError("InvalidGrantError", "Refresh token has expired or was already used")
	}

	auth.RefreshToken.Invalidated = true
	return auth, nil
}

// SaveTokens atomically updates the access and refresh tokens for the specified authorization ID while verifying the previous refresh token.
// Passing an empty expectedOldRefreshToken disables the previous-refresh-token comparison; callers must not rely on the comparison when passing an empty value.
func (this *InMemoryOAuth2AuthorizationService) SaveTokens(authID, expectedOldRefreshToken string, accessToken *OAuth2AccessToken, refreshToken *OAuth2RefreshToken) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

	auth, ok := this.byID[authID]
	if !ok {
		return NewError("AuthorizationNotFound", "authorization not found by id: "+authID)
	}

	if expectedOldRefreshToken != "" && (auth.RefreshToken == nil || auth.RefreshToken.TokenValue != expectedOldRefreshToken) {
		return NewError("InvalidGrantError", "Refresh token mismatch or already replaced")
	}

	auth.AccessToken = accessToken
	if refreshToken != nil {
		auth.RefreshToken = refreshToken
	}

	return this.saveLocked(auth)
}

// FindByID retrieves an OAuth2Authorization by its ID from memory.
func (this *InMemoryOAuth2AuthorizationService) FindByID(id string) (*OAuth2Authorization, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	auth, ok := this.byID[id]
	if !ok {
		return nil, NewError("AuthorizationNotFound", "authorization not found by id: "+id)
	}
	return auth, nil
}

// FindByToken retrieves an OAuth2Authorization by token value and required tokenType selector ("code", "access_token", or "refresh_token").
func (this *InMemoryOAuth2AuthorizationService) FindByToken(token, tokenType string) (*OAuth2Authorization, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	switch tokenType {
	case OAuth2ParameterCode:
		if auth, ok := this.byAuthCode[token]; ok {
			return auth, nil
		}
	case "access_token":
		if auth, ok := this.byAccessToken[token]; ok {
			return auth, nil
		}
	case "refresh_token":
		if auth, ok := this.byRefreshToken[token]; ok {
			return auth, nil
		}
	default:
	}
	return nil, NewError("AuthorizationNotFound", "authorization not found for token type "+tokenType)
}
