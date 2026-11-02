package login

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

const sessionAuthRequestKey = "oauth2_authorization_request"

// AuthorizationRequestRepository manages persisting authorization requests between the redirect and callback
type AuthorizationRequestRepository interface {
	LoadAuthorizationRequest(handler SecurityHandler) *OAuth2AuthorizationRequest
	SaveAuthorizationRequest(authRequest *OAuth2AuthorizationRequest, handler SecurityHandler)
	RemoveAuthorizationRequest(handler SecurityHandler) *OAuth2AuthorizationRequest
}

// SessionAuthorizationRequestRepository persists the request in the user session
type SessionAuthorizationRequestRepository struct{}

func (this SessionAuthorizationRequestRepository) New() *SessionAuthorizationRequestRepository {
	return &this
}

func NewSessionAuthorizationRequestRepository() *SessionAuthorizationRequestRepository {
	return SessionAuthorizationRequestRepository{}.New()
}

func (this *SessionAuthorizationRequestRepository) LoadAuthorizationRequest(handler SecurityHandler) *OAuth2AuthorizationRequest {
	val := handler.SessionValue(sessionAuthRequestKey)
	if req, ok := val.(*OAuth2AuthorizationRequest); ok {
		return req
	}
	return nil
}

func (this *SessionAuthorizationRequestRepository) SaveAuthorizationRequest(authRequest *OAuth2AuthorizationRequest, handler SecurityHandler) {
	handler.SetSessionValue(sessionAuthRequestKey, authRequest)
}

func (this *SessionAuthorizationRequestRepository) RemoveAuthorizationRequest(handler SecurityHandler) *OAuth2AuthorizationRequest {
	req := this.LoadAuthorizationRequest(handler)
	handler.SetSessionValue(sessionAuthRequestKey, nil)
	return req
}

// GenerateAuthorizationRequest creates an authorization request with PKCE and state.
// If a SecurityHandler is provided, relative redirect URIs and default callback paths
// are resolved to absolute URIs based on the current request's scheme and host (respecting trusted proxy headers).
func GenerateAuthorizationRequest(reg *ClientRegistration, handlers ...SecurityHandler) (*OAuth2AuthorizationRequest, Error) {
	// Generate random state
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, NewError("CryptoError", fmt.Sprintf("failed to generate random state: %s", err))
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Generate PKCE code_verifier and code_challenge (S256)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, NewError("CryptoError", fmt.Sprintf("failed to generate code_verifier: %s", err))
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	redirectURI := reg.RedirectURI
	if redirectURI == "" {
		redirectURI = "/login/oauth2/code/" + reg.RegistrationID
	}

	if len(handlers) > 0 && handlers[0] != nil && !strings.Contains(redirectURI, "://") {
		handler := handlers[0]
		scheme := "http"
		proto := handler.Header("X-Forwarded-Proto")
		if proto != "" {
			parts := strings.Split(proto, ",")
			scheme = strings.TrimSpace(parts[0])
		} else if u := handler.URL(); u != nil && u.Scheme != "" {
			scheme = u.Scheme
		}

		host := "localhost"
		fHost := handler.Header("X-Forwarded-Host")
		if fHost != "" {
			parts := strings.Split(fHost, ",")
			host = strings.TrimSpace(parts[0])
		} else if h := handler.Header("Host"); h != "" {
			host = h
		} else if u := handler.URL(); u != nil && u.Host != "" {
			host = u.Host
		}

		if fPort := handler.Header("X-Forwarded-Port"); fPort != "" && !strings.Contains(host, ":") {
			portStr := strings.TrimSpace(strings.Split(fPort, ",")[0])
			if (scheme == "http" && portStr != "80") || (scheme == "https" && portStr != "443") {
				host = host + ":" + portStr
			}
		}

		if !strings.HasPrefix(redirectURI, "/") {
			redirectURI = "/" + redirectURI
		}
		redirectURI = fmt.Sprintf("%s://%s%s", scheme, host, redirectURI)
	}

	return &OAuth2AuthorizationRequest{
		AuthorizationURI:    reg.ProviderDetails.AuthorizationURI,
		ClientID:            reg.ClientID,
		RedirectURI:         redirectURI,
		Scopes:              reg.Scopes,
		State:               state,
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		AdditionalParams:    make(map[string]string),
	}, nil
}

// BuildAuthorizationURI formats the redirect URL with query parameters
func BuildAuthorizationURI(req *OAuth2AuthorizationRequest) string {
	u, err := url.Parse(req.AuthorizationURI)
	if err != nil {
		NewErrorFrom(err).LogError()
		return req.AuthorizationURI
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", req.ClientID)
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("state", req.State)
	if len(req.Scopes) > 0 {
		q.Set("scope", strings.Join(req.Scopes, " "))
	}
	if req.CodeChallenge != "" {
		q.Set("code_challenge", req.CodeChallenge)
		q.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	for k, v := range req.AdditionalParams {
		q.Set(k, v)
	}

	u.RawQuery = q.Encode()
	return u.String()
}
