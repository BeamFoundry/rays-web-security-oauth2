package login_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/login"
)

func FuzzBuildAuthorizationURI(f *testing.F) {
	// Seed corpus
	f.Add("https://accounts.google.com/o/oauth2/v2/auth", "client-123", "https://app.com/callback", "state-abc", "S256")
	f.Add("https://auth.example.com/oauth2/authorize?existing=param", "cid", "https://app.com/cb", "xyz", "S256")
	f.Add("invalid-uri-scheme", "c", "/cb", "s", "plain")
	f.Add("https://auth.com/auth", "client-id-with-special!@#$%", "https://app.com/cb?param=1&param=2", "state\nwith\r\nnewlines", "S256")
	f.Add("", "", "", "", "")

	f.Fuzz(func(_ *testing.T, authURI, clientID, redirectURI, state, method string) {
		hash := sha256.Sum256([]byte(state))
		challenge := base64.RawURLEncoding.EncodeToString(hash[:])

		req := &OAuth2AuthorizationRequest{
			AuthorizationURI:    authURI,
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scopes:              []string{"openid", "profile"},
			State:               state,
			CodeVerifier:        state,
			CodeChallenge:       challenge,
			CodeChallengeMethod: method,
			AdditionalParams:    map[string]string{"prompt": "consent"},
		}

		// Must never panic on arbitrary input
		_ = BuildAuthorizationURI(req)
	})
}
