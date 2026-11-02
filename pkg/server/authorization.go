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
	Save(authorization *OAuth2Authorization) Error
	Remove(authorization *OAuth2Authorization) Error
	FindByID(id string) (*OAuth2Authorization, Error)
	FindByToken(token, tokenType string) (*OAuth2Authorization, Error)
	InvalidateAuthorizationCode(code string) (*OAuth2Authorization, Error)
}

type trackedTokens struct {
	code         string
	accessToken  string
	refreshToken string
}

// InMemoryOAuth2AuthorizationService stores authorizations in memory
type InMemoryOAuth2AuthorizationService struct {
	mu             *sync.RWMutex
	byID           map[string]*OAuth2Authorization
	byAuthCode     map[string]*OAuth2Authorization
	byAccessToken  map[string]*OAuth2Authorization
	byRefreshToken map[string]*OAuth2Authorization
	tracked        map[string]trackedTokens
}

func (this InMemoryOAuth2AuthorizationService) New() *InMemoryOAuth2AuthorizationService {
	this.mu = &sync.RWMutex{}
	this.byID = make(map[string]*OAuth2Authorization)
	this.byAuthCode = make(map[string]*OAuth2Authorization)
	this.byAccessToken = make(map[string]*OAuth2Authorization)
	this.byRefreshToken = make(map[string]*OAuth2Authorization)
	this.tracked = make(map[string]trackedTokens)
	return &this
}

func NewInMemoryOAuth2AuthorizationService() *InMemoryOAuth2AuthorizationService {
	return InMemoryOAuth2AuthorizationService{}.New()
}

func (this *InMemoryOAuth2AuthorizationService) Save(auth *OAuth2Authorization) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

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

func (this *InMemoryOAuth2AuthorizationService) FindByID(id string) (*OAuth2Authorization, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	auth, ok := this.byID[id]
	if !ok {
		return nil, NewError("AuthorizationNotFound", "authorization not found by id: "+id)
	}
	return auth, nil
}

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
