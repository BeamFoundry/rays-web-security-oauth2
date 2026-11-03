package login

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

const (
	// sessionAuthRequestKey is the default HTTP session attribute key used to store pending OAuth2AuthorizationRequest instances.
	sessionAuthRequestKey = "oauth2_authorization_request"
	// schemeHTTP is the standard unencrypted HTTP URI scheme.
	schemeHTTP = "http"
	// schemeHTTPS is the standard TLS-encrypted HTTPS URI scheme.
	schemeHTTPS = "https"
)

// AuthorizationRequestConfig holds options for GenerateAuthorizationRequest
type AuthorizationRequestConfig struct {
	BaseURL      string
	TrustedProxy bool
}

// AuthorizationRequestOption configures an AuthorizationRequestConfig
type AuthorizationRequestOption func(*AuthorizationRequestConfig)

// WithBaseURL configures a static base URL for resolving relative redirect URIs
func WithBaseURL(baseURL string) AuthorizationRequestOption {
	return func(c *AuthorizationRequestConfig) {
		c.BaseURL = baseURL
	}
}

// WithTrustedProxy enables or disables using X-Forwarded-* headers to determine scheme/host/port
func WithTrustedProxy(trusted bool) AuthorizationRequestOption {
	return func(c *AuthorizationRequestConfig) {
		c.TrustedProxy = trusted
	}
}

// isHostChar reports whether rune c is a valid DNS hostname label character at position idx of a label of given length.
func isHostChar(c rune, idx, length int) bool {
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
		return true
	}
	return c == '-' && idx > 0 && idx < length-1
}

// isValidHost validates that h is a well-formed hostname or IP address with an optional valid port.
func isValidHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	for _, r := range h {
		if r <= ' ' || r == '/' || r == '\\' || r == '?' || r == '#' || r == '@' {
			return false
		}
	}
	hostname, port, err := net.SplitHostPort(h)
	if err == nil {
		portNum, pErr := strconv.Atoi(port)
		if pErr != nil || portNum <= 0 || portNum > 65535 {
			return false
		}
		h = hostname
	}
	h = strings.Trim(h, "[]")
	if ip := net.ParseIP(h); ip != nil {
		return true
	}
	for part := range strings.SplitSeq(h, ".") {
		if part == "" || len(part) > 63 {
			return false
		}
		for i, c := range part {
			if !isHostChar(c, i, len(part)) {
				return false
			}
		}
	}
	return true
}

// resolveForwardedHeaders extracts and validates scheme and host from X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-Port headers.
func resolveForwardedHeaders(handler SecurityHandler, defaultScheme, defaultHost string) (scheme, host string) {
	scheme = defaultScheme
	host = defaultHost

	proto := handler.Header("X-Forwarded-Proto")
	if proto != "" {
		p := strings.TrimSpace(strings.Split(proto, ",")[0])
		if p == schemeHTTP || p == schemeHTTPS {
			scheme = p
		}
	}

	fHost := handler.Header("X-Forwarded-Host")
	if fHost != "" {
		rawHost := strings.TrimSpace(strings.Split(fHost, ",")[0])
		if isValidHost(rawHost) {
			host = rawHost
		}
	}

	fPort := handler.Header("X-Forwarded-Port")
	if fPort != "" && !strings.Contains(host, ":") {
		portStr := strings.TrimSpace(strings.Split(fPort, ",")[0])
		if portNum, pErr := strconv.Atoi(portStr); pErr == nil && portNum > 0 && portNum <= 65535 {
			if (scheme == schemeHTTP && portStr != "80") || (scheme == schemeHTTPS && portStr != "443") {
				host = host + ":" + portStr
			}
		}
	}

	return scheme, host
}

// AuthorizationRequestRepository manages persisting authorization requests between the redirect and callback
type AuthorizationRequestRepository interface {
	// LoadAuthorizationRequest retrieves the OAuth2AuthorizationRequest associated with the current request, or nil if none exists.
	LoadAuthorizationRequest(handler SecurityHandler) *OAuth2AuthorizationRequest
	// SaveAuthorizationRequest persists the OAuth2AuthorizationRequest for the current request context.
	SaveAuthorizationRequest(authRequest *OAuth2AuthorizationRequest, handler SecurityHandler)
	// RemoveAuthorizationRequest removes and returns the persisted OAuth2AuthorizationRequest for the current request context.
	RemoveAuthorizationRequest(handler SecurityHandler) *OAuth2AuthorizationRequest
}

// SessionAuthorizationRequestRepository persists the request in the user session
type SessionAuthorizationRequestRepository struct{}

// New creates a new SessionAuthorizationRequestRepository.
func (this SessionAuthorizationRequestRepository) New() *SessionAuthorizationRequestRepository {
	return &this
}

// NewSessionAuthorizationRequestRepository creates a new SessionAuthorizationRequestRepository.
func NewSessionAuthorizationRequestRepository() *SessionAuthorizationRequestRepository {
	return SessionAuthorizationRequestRepository{}.New()
}

// LoadAuthorizationRequest retrieves the OAuth2AuthorizationRequest from the HTTP session.
func (this *SessionAuthorizationRequestRepository) LoadAuthorizationRequest(handler SecurityHandler) *OAuth2AuthorizationRequest {
	val := handler.SessionValue(sessionAuthRequestKey)
	if req, ok := val.(*OAuth2AuthorizationRequest); ok {
		return req
	}
	return nil
}

// SaveAuthorizationRequest stores the OAuth2AuthorizationRequest in the HTTP session.
func (this *SessionAuthorizationRequestRepository) SaveAuthorizationRequest(authRequest *OAuth2AuthorizationRequest, handler SecurityHandler) {
	handler.SetSessionValue(sessionAuthRequestKey, authRequest)
}

// RemoveAuthorizationRequest retrieves and deletes the OAuth2AuthorizationRequest from the HTTP session.
func (this *SessionAuthorizationRequestRepository) RemoveAuthorizationRequest(handler SecurityHandler) *OAuth2AuthorizationRequest {
	req := this.LoadAuthorizationRequest(handler)
	handler.SetSessionValue(sessionAuthRequestKey, nil)
	return req
}

// GenerateAuthorizationRequest creates an authorization request with PKCE and state.
// If a SecurityHandler or options are provided, relative redirect URIs and default callback paths
// are resolved to absolute URIs based on a configured base URL or request host/scheme (respecting trusted proxy setting).
func GenerateAuthorizationRequest(reg *ClientRegistration, args ...any) (*OAuth2AuthorizationRequest, Error) {
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

	var handler SecurityHandler
	var cfg AuthorizationRequestConfig
	for _, arg := range args {
		switch v := arg.(type) {
		case SecurityHandler:
			handler = v
		case AuthorizationRequestOption:
			v(&cfg)
		case *AuthorizationRequestConfig:
			if v != nil {
				cfg = *v
			}
		default:
		}
	}

	if !strings.Contains(redirectURI, "://") {
		if cfg.BaseURL != "" {
			base, pErr := url.Parse(cfg.BaseURL)
			if pErr != nil {
				return nil, NewError("InvalidConfigurationError", fmt.Sprintf("invalid BaseURL: %s", pErr))
			}
			if base.Scheme != schemeHTTP && base.Scheme != schemeHTTPS {
				return nil, NewError("InvalidConfigurationError", fmt.Sprintf("invalid BaseURL scheme %q: must be http or https", base.Scheme))
			}
			if base.Host == "" || !isValidHost(base.Host) {
				return nil, NewError("InvalidConfigurationError", fmt.Sprintf("invalid BaseURL host %q", base.Host))
			}

			basePath := strings.TrimSuffix(base.Path, "/")
			relPath := "/" + strings.TrimPrefix(redirectURI, "/")
			fullPath := basePath + relPath
			redirectURI = fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, fullPath)
		} else if handler != nil && cfg.TrustedProxy {
			scheme, host := resolveForwardedHeaders(handler, schemeHTTP, "")
			if host != "" && isValidHost(host) && (scheme == schemeHTTP || scheme == schemeHTTPS) {
				if !strings.HasPrefix(redirectURI, "/") {
					redirectURI = "/" + redirectURI
				}
				redirectURI = fmt.Sprintf("%s://%s%s", scheme, host, redirectURI)
			}
		}
	}

	u, pErr := url.Parse(redirectURI)
	if pErr != nil || !u.IsAbs() {
		return nil, NewError("InvalidConfigurationError", "redirect_uri must be an absolute URI: configure a valid BaseURL or valid trusted forwarded headers")
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
	for k, v := range req.AdditionalParams {
		q.Set(k, v)
	}
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

	u.RawQuery = q.Encode()
	return u.String()
}
