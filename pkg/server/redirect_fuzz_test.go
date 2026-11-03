package server_test

import (
	"net/url"
	"testing"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/server"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/web"
)

// FuzzHandleAuthorizeRedirect fuzzes the authorization endpoint redirect URI and state validation.
func FuzzHandleAuthorizeRedirect(f *testing.F) {
	km, err := RSAKeyManager{}.New(2048, "fuzz-key")
	if err != nil {
		f.Fatalf("failed to create key: %v", err)
	}

	settings := AuthorizationServerSettings{}.NewDefault("https://auth.beamfoundry.com")
	encoder := DefaultJwtEncoder{}.New(km)
	generator := JwtOAuth2TokenGenerator{}.New(encoder, settings.Issuer)

	client := &RegisteredClient{
		ID:                      "fuzz-client-id",
		ClientID:                "fuzz-app",
		ClientSecret:            "secret",
		AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeAuthorizationCode},
		RedirectURIs:            []string{"https://app.example.com/callback"},
		Scopes:                  []string{"openid", "profile"},
		AccessTokenTimeToLive:   10 * time.Minute,
	}

	clientRepo := InMemoryRegisteredClientRepository{}.New(client)
	authService := InMemoryOAuth2AuthorizationService{}.New()
	contextHolder := &mockSecurityContextHolder{}

	// Authenticated principal
	authUser := DefaultOAuth2User{}.New(
		nil,
		map[string]any{"sub": "fuzz-user"},
		"sub",
	)
	contextHolder.GetContext().SetAuthentication(
		OAuth2AuthenticationToken{}.New(authUser, nil, "internal"),
	)

	filter := OAuth2AuthorizationServerFilter{}.New(
		settings,
		clientRepo,
		authService,
		generator,
		km,
		contextHolder,
	)

	router := NewMockSecurityRouter()
	filter.RegisterSecurityEndpoint(router)

	// Seeds for redirect_uri and state
	f.Add("https://app.example.com/callback", "normal-state-123")
	f.Add("https://app.example.com/callback?extra=param", "state-with-query")
	f.Add("https://app.example.com@evil.com/callback", "userinfo-spoof")
	f.Add("https://evil.com/callback", "completely-wrong-domain")
	f.Add("//evil.com/callback", "protocol-relative")
	f.Add("javascript:alert(1)", "javascript-scheme")
	f.Add("data:text/html,<script>alert(1)</script>", "data-scheme")
	f.Add("https://app.example.com/callback/../../evil", "path-traversal")
	f.Add("https://app.example.com%0aSet-Cookie:evil=1", "crlf-injection")
	f.Add("", "")
	f.Add(" ", " ")
	f.Add("\x00\xff", "\x01\x02")

	f.Fuzz(func(_ *testing.T, redirectURI, state string) {
		reqURL, parseErr := url.Parse("https://auth.beamfoundry.com/oauth2/authorize" +
			"?response_type=code" +
			"&client_id=fuzz-app" +
			"&redirect_uri=" + url.QueryEscape(redirectURI) +
			"&state=" + url.QueryEscape(state))
		if parseErr != nil {
			return
		}

		handler := NewMockSecurityHandler(HttpMethods.GET, reqURL)

		// Must never panic on arbitrary redirect_uri or state inputs
		if execErr := router.Execute(handler); execErr != nil {
			NewErrorFrom(execErr).LogError()
		}
	})
}
