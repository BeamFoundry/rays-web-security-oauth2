// Package server_test contains unit and fuzz tests for the OAuth 2.1 authorization server.
package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/server"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
	_ "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/web"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// TestServer runs the Ginkgo test suite for the OAuth2 authorization server package.
func TestServer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OAuth2 Authorization Server Suite")
}

// mockSecurityContext is an in-memory test double for SecurityContext.
type mockSecurityContext struct {
	auth  Authentication
	debug string
}

// GetAuthentication returns the stored Authentication.
func (this *mockSecurityContext) GetAuthentication() Authentication { return this.auth }

// SetAuthentication sets the current Authentication in the context.
func (this *mockSecurityContext) SetAuthentication(a Authentication) { this.auth = a }

// SetHTTPPolicyDebugValue sets the HTTP policy debug string.
func (this *mockSecurityContext) SetHTTPPolicyDebugValue(debug string) { this.debug = debug }

// GetHTTPPolicyDebugValue returns the HTTP policy debug string.
func (this *mockSecurityContext) GetHTTPPolicyDebugValue() string { return this.debug }

// mockSecurityContextHolder is an in-memory test double for SecurityContextHolder.
type mockSecurityContextHolder struct {
	ctx SecurityContext
}

// ClearContext resets the stored SecurityContext to nil.
func (this *mockSecurityContextHolder) ClearContext() { this.ctx = nil }

// SetContext stores the given SecurityContext.
func (this *mockSecurityContextHolder) SetContext(sc SecurityContext) {
	this.ctx = sc
}

// GetContext returns the current SecurityContext, lazily initializing one if nil.
func (this *mockSecurityContextHolder) GetContext() SecurityContext {
	if this.ctx == nil {
		this.ctx = &mockSecurityContext{}
	}
	return this.ctx
}

var _ = Describe("RegisteredClientRepository", func() {
	It("finds client by ID and ClientID", func() {
		client := &RegisteredClient{
			ID:           "uuid-client-1",
			ClientID:     "portal-app",
			ClientSecret: "secret123",
			ClientName:   "Portal Application",
			RedirectURIs: []string{"https://portal.example.com/callback"},
		}

		repo := InMemoryRegisteredClientRepository{}.New(client)

		byID, err := repo.FindByID("uuid-client-1")
		Expect(err).NotTo(HaveOccurred())
		Expect(byID.ClientID).To(Equal("portal-app"))

		byClientID, err := repo.FindByClientID("portal-app")
		Expect(err).NotTo(HaveOccurred())
		Expect(byClientID.ID).To(Equal("uuid-client-1"))

		_, err = repo.FindByClientID("non-existent")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("OAuth2AuthorizationService", func() {
	It("saves, finds, and removes authorizations by various token types", func() {
		service := InMemoryOAuth2AuthorizationService{}.New()

		auth := &OAuth2Authorization{
			ID:                 "auth-1",
			RegisteredClientID: "client-1",
			PrincipalName:      "alice",
			AuthorizationCode: &AuthorizationCode{
				Value: "code-12345",
			},
			AccessToken: &OAuth2AccessToken{
				TokenValue: "access-token-999",
			},
			RefreshToken: &OAuth2RefreshToken{
				TokenValue: "refresh-token-888",
			},
		}

		err := service.Save(auth)
		Expect(err).NotTo(HaveOccurred())

		// By ID
		byId, err := service.FindByID("auth-1")
		Expect(err).NotTo(HaveOccurred())
		Expect(byId.PrincipalName).To(Equal("alice"))

		// By Code
		byCode, err := service.FindByToken("code-12345", "code")
		Expect(err).NotTo(HaveOccurred())
		Expect(byCode.ID).To(Equal("auth-1"))

		// By Access Token
		byAccess, err := service.FindByToken("access-token-999", "access_token")
		Expect(err).NotTo(HaveOccurred())
		Expect(byAccess.ID).To(Equal("auth-1"))

		// By Refresh Token
		byRefresh, err := service.FindByToken("refresh-token-888", "refresh_token")
		Expect(err).NotTo(HaveOccurred())
		Expect(byRefresh.ID).To(Equal("auth-1"))

		// Remove
		err = service.Remove(auth)
		Expect(err).NotTo(HaveOccurred())

		_, err = service.FindByID("auth-1")
		Expect(err).To(HaveOccurred())
	})

	It("cleans up stale token indexes when tokens are rotated on save", func() {
		service := InMemoryOAuth2AuthorizationService{}.New()

		auth := &OAuth2Authorization{
			ID:                 "auth-rot",
			RegisteredClientID: "client-rot",
			PrincipalName:      "alice",
			AuthorizationCode: &AuthorizationCode{
				Value: "code-v1",
			},
			AccessToken: &OAuth2AccessToken{
				TokenValue: "at-v1",
			},
			RefreshToken: &OAuth2RefreshToken{
				TokenValue: "rt-v1",
			},
		}

		Expect(service.Save(auth)).NotTo(HaveOccurred())

		// Rotate tokens
		auth.AuthorizationCode = &AuthorizationCode{Value: "code-v2"}
		auth.AccessToken = &OAuth2AccessToken{TokenValue: "at-v2"}
		auth.RefreshToken = &OAuth2RefreshToken{TokenValue: "rt-v2"}

		Expect(service.Save(auth)).NotTo(HaveOccurred())

		// Old tokens must no longer be found
		_, err := service.FindByToken("code-v1", "code")
		Expect(err).To(HaveOccurred())
		_, err = service.FindByToken("at-v1", "access_token")
		Expect(err).To(HaveOccurred())
		_, err = service.FindByToken("rt-v1", "refresh_token")
		Expect(err).To(HaveOccurred())

		// New tokens must be found
		byCode, err := service.FindByToken("code-v2", "code")
		Expect(err).NotTo(HaveOccurred())
		Expect(byCode.ID).To(Equal("auth-rot"))
		byAccess, err := service.FindByToken("at-v2", "access_token")
		Expect(err).NotTo(HaveOccurred())
		Expect(byAccess.ID).To(Equal("auth-rot"))
		byRefresh, err := service.FindByToken("rt-v2", "refresh_token")
		Expect(err).NotTo(HaveOccurred())
		Expect(byRefresh.ID).To(Equal("auth-rot"))

		// Another auth with token must not be deleted when auth-rot is removed
		otherAuth := &OAuth2Authorization{
			ID:                 "auth-other",
			RegisteredClientID: "client-rot",
			PrincipalName:      "bob",
			AccessToken:        &OAuth2AccessToken{TokenValue: "at-other"},
		}
		Expect(service.Save(otherAuth)).NotTo(HaveOccurred())

		Expect(service.Remove(auth)).NotTo(HaveOccurred())

		// auth-rot tokens gone
		_, err = service.FindByToken("at-v2", "access_token")
		Expect(err).To(HaveOccurred())

		// otherAuth token preserved
		byOther, err := service.FindByToken("at-other", "access_token")
		Expect(err).NotTo(HaveOccurred())
		Expect(byOther.ID).To(Equal("auth-other"))
	})
})

var _ = Describe("JwtOAuth2TokenGenerator", func() {
	It("generates signed JWT access token and refresh token", func() {
		km, err := RSAKeyManager{}.New(2048, "srv-key")
		Expect(err).NotTo(HaveOccurred())

		encoder := DefaultJwtEncoder{}.New(km)
		generator := JwtOAuth2TokenGenerator{}.New(encoder, "https://auth.beamfoundry.com")

		client := &RegisteredClient{
			ID:       "c-1",
			ClientID: "test-client",
			AuthorizationGrantTypes: []AuthorizationGrantType{
				GrantTypeAuthorizationCode,
				GrantTypeRefreshToken,
			},
			AccessTokenTimeToLive:  15 * time.Minute,
			RefreshTokenTimeToLive: 24 * time.Hour,
		}

		auth := &OAuth2Authorization{
			ID:                 "auth-id",
			RegisteredClientID: "c-1",
			PrincipalName:      "charlie",
			AuthorizedScopes:   []string{"openid", "profile", "read"},
		}

		accessTok, refreshTok, err := generator.Generate(auth, client)
		Expect(err).NotTo(HaveOccurred())
		Expect(accessTok).NotTo(BeNil())
		Expect(refreshTok).NotTo(BeNil())

		// Verify with decoder
		decoder := NimbusJwtDecoder{}.New(km).WithIssuer("https://auth.beamfoundry.com")
		decoded, err := decoder.Decode(accessTok.TokenValue)
		Expect(err).NotTo(HaveOccurred())
		Expect(decoded.Subject()).To(Equal("charlie"))
		Expect(decoded.Issuer()).To(Equal("https://auth.beamfoundry.com"))
		Expect(decoded.Claims).To(HaveKeyWithValue("scope", "openid profile read"))
	})
})

var _ = Describe("OAuth2AuthorizationServerFilter Endpoints", func() {
	var (
		settings         *AuthorizationServerSettings
		km               *RSAKeyManager
		clientRepo       *InMemoryRegisteredClientRepository
		authService      *InMemoryOAuth2AuthorizationService
		generator        OAuth2TokenGenerator
		contextHolder    *mockSecurityContextHolder
		filter           *OAuth2AuthorizationServerFilter
		router           *MockSecurityRouter
		registeredClient *RegisteredClient
	)

	BeforeEach(func() {
		var err error
		km, err = RSAKeyManager{}.New(2048, "auth-srv-test-key")
		Expect(err).NotTo(HaveOccurred())

		settings = AuthorizationServerSettings{}.NewDefault("https://auth.beamfoundry.com")
		encoder := DefaultJwtEncoder{}.New(km)
		generator = JwtOAuth2TokenGenerator{}.New(encoder, settings.Issuer)

		registeredClient = &RegisteredClient{
			ID:           "client-id-1",
			ClientID:     "my-spa-app",
			ClientSecret: "client-secret-123",
			ClientName:   "My SPA App",
			AuthorizationGrantTypes: []AuthorizationGrantType{
				GrantTypeAuthorizationCode,
				GrantTypeRefreshToken,
				GrantTypeClientCredentials,
			},
			RedirectURIs:           []string{"https://my-spa.example.com/callback"},
			Scopes:                 []string{"openid", "profile", "orders"},
			RequireProofKey:        true,
			AccessTokenTimeToLive:  1 * time.Hour,
			RefreshTokenTimeToLive: 24 * time.Hour,
		}

		clientRepo = InMemoryRegisteredClientRepository{}.New(registeredClient)
		authService = InMemoryOAuth2AuthorizationService{}.New()
		contextHolder = &mockSecurityContextHolder{}

		filter = OAuth2AuthorizationServerFilter{}.New(
			settings,
			clientRepo,
			authService,
			generator,
			km,
			contextHolder,
		)

		router = NewMockSecurityRouter()
		filter.RegisterSecurityEndpoint(router)
	})

	Context("Discovery Metadata endpoint (/.well-known/openid-configuration)", func() {
		It("serves OpenID Provider Configuration Document", func() {
			u, err := url.Parse("https://auth.beamfoundry.com/.well-known/openid-configuration")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			err = router.Execute(handler)
			Expect(err).NotTo(HaveOccurred())

			var meta map[string]any
			err = json.Unmarshal(handler.Res.Body.Bytes(), &meta)
			Expect(err).NotTo(HaveOccurred())

			Expect(meta).To(HaveKeyWithValue("issuer", "https://auth.beamfoundry.com"))
			Expect(meta).To(HaveKeyWithValue("authorization_endpoint", "https://auth.beamfoundry.com/oauth2/authorize"))
			Expect(meta).To(HaveKeyWithValue("token_endpoint", "https://auth.beamfoundry.com/oauth2/token"))
			Expect(meta).To(HaveKeyWithValue("jwks_uri", "https://auth.beamfoundry.com/oauth2/jwks"))
		})
	})

	Context("JWK Set endpoint (/oauth2/jwks)", func() {
		It("serves the public JSON Web Key Set", func() {
			u, err := url.Parse("https://auth.beamfoundry.com/oauth2/jwks")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			err = router.Execute(handler)
			Expect(err).NotTo(HaveOccurred())

			var jwks map[string]any
			err = json.Unmarshal(handler.Res.Body.Bytes(), &jwks)
			Expect(err).NotTo(HaveOccurred())

			keys, ok := jwks["keys"].([]any)
			Expect(ok).To(BeTrue())
			Expect(keys).To(HaveLen(1))
			firstKey := keys[0].(map[string]any)
			Expect(firstKey).To(HaveKeyWithValue("kid", "auth-srv-test-key"))
			Expect(firstKey).To(HaveKeyWithValue("kty", "RSA"))
		})
	})

	Context("Full Authorization Code Grant with PKCE Flow", func() {
		It("authorizes with PKCE S256, exchanges code for tokens, and allows introspection & revocation", func() {
			// Step 1: Simulate authenticated user in SecurityContext
			authUser := DefaultOAuth2User{}.New(
				[]GrantedAuthority{Authority("ROLE_USER")},
				map[string]any{"sub": "john_doe"},
				"sub",
			)
			contextHolder.GetContext().SetAuthentication(
				OAuth2AuthenticationToken{}.New(authUser, authUser.GetAuthorities(), "internal"),
			)

			// Step 2: PKCE code_verifier & code_challenge
			verifier := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
			hash := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(hash[:])

			// Step 3: Call GET /oauth2/authorize
			authURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize" +
				"?response_type=code" +
				"&client_id=my-spa-app" +
				"&redirect_uri=" + url.QueryEscape("https://my-spa.example.com/callback") +
				"&scope=openid+orders" +
				"&code_challenge=" + challenge +
				"&code_challenge_method=S256" +
				"&state=xyz123")
			Expect(err).NotTo(HaveOccurred())

			authHandler := NewMockSecurityHandler(HttpMethods.GET, authURI)
			err = router.Execute(authHandler)
			// MockSecurityHandler.Redirect returns DefaultSecurityFilterChainException
			Expect(err).To(HaveOccurred())
			redirectEx := &DefaultSecurityFilterChainException{}
			ok := errors.As(err, &redirectEx)
			Expect(ok).To(BeTrue())
			Expect(redirectEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))

			targetRedirect, err := url.Parse(redirectEx.To())
			Expect(err).NotTo(HaveOccurred())
			Expect(targetRedirect.Host).To(Equal("my-spa.example.com"))
			authCode := targetRedirect.Query().Get("code")
			Expect(authCode).NotTo(BeEmpty())
			Expect(targetRedirect.Query().Get("state")).To(Equal("xyz123"))

			// Step 4: Call POST /oauth2/token with authorization_code and code_verifier
			tokenURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(err).NotTo(HaveOccurred())
			tokenHandler := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			tokenHandler.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			tokenHandler.SetFormValue("grant_type", "authorization_code")
			tokenHandler.SetFormValue("code", authCode)
			tokenHandler.SetFormValue("redirect_uri", "https://my-spa.example.com/callback")
			tokenHandler.SetFormValue("code_verifier", verifier)

			err = router.Execute(tokenHandler)
			Expect(err).NotTo(HaveOccurred())

			var tokenResp map[string]any
			err = json.Unmarshal(tokenHandler.Res.Body.Bytes(), &tokenResp)
			Expect(err).NotTo(HaveOccurred())
			Expect(tokenResp).To(HaveKey("access_token"))
			Expect(tokenResp).To(HaveKey("refresh_token"))
			accessTokenStr, ok := tokenResp["access_token"].(string)
			Expect(ok).To(BeTrue())
			Expect(accessTokenStr).NotTo(BeEmpty())

			// Step 5: Introspect the access token via POST /oauth2/introspect
			introURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/introspect")
			Expect(err).NotTo(HaveOccurred())
			introHandler := NewMockSecurityHandler(HttpMethods.POST, introURI)
			introHandler.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			introHandler.SetFormValue("token", accessTokenStr)

			err = router.Execute(introHandler)
			Expect(err).NotTo(HaveOccurred())

			var introResp map[string]any
			err = json.Unmarshal(introHandler.Res.Body.Bytes(), &introResp)
			Expect(err).NotTo(HaveOccurred())
			Expect(introResp).To(HaveKeyWithValue("active", true))
			Expect(introResp).To(HaveKeyWithValue("sub", "john_doe"))
			Expect(introResp).To(HaveKeyWithValue("client_id", "my-spa-app"))

			// Step 6: Revoke the access token via POST /oauth2/revoke
			revokeURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/revoke")
			Expect(err).NotTo(HaveOccurred())
			revokeHandler := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			revokeHandler.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			revokeHandler.SetFormValue("token", accessTokenStr)

			err = router.Execute(revokeHandler)
			Expect(err).NotTo(HaveOccurred())

			// Also revoke the refresh token via POST /oauth2/revoke
			refreshTokenStr, ok := tokenResp["refresh_token"].(string)
			Expect(ok).To(BeTrue())
			revokeHandlerRT := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			revokeHandlerRT.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			revokeHandlerRT.SetFormValue("token", refreshTokenStr)
			Expect(router.Execute(revokeHandlerRT)).To(Succeed())

			// Step 7: Introspect again, verify active=false
			introHandler2 := NewMockSecurityHandler(HttpMethods.POST, introURI)
			introHandler2.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			introHandler2.SetFormValue("token", accessTokenStr)

			err = router.Execute(introHandler2)
			Expect(err).NotTo(HaveOccurred())

			var introResp2 map[string]any
			err = json.Unmarshal(introHandler2.Res.Body.Bytes(), &introResp2)
			Expect(err).NotTo(HaveOccurred())
			Expect(introResp2).To(HaveKeyWithValue("active", false))
		})

		It("handles client_credentials grant and returns access token", func() {
			tokenURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			handler.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			handler.SetFormValue("grant_type", "client_credentials")

			err = router.Execute(handler)
			Expect(err).NotTo(HaveOccurred())

			var resp map[string]any
			err = json.Unmarshal(handler.Res.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp).To(HaveKey("access_token"))
			Expect(resp).To(HaveKeyWithValue("token_type", "Bearer"))
		})

		It("handles refresh_token grant and refreshes access token", func() {
			// Save an existing authorization with a refresh token
			auth := &OAuth2Authorization{
				ID:                 "refresh-auth-1",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-to-refresh",
				//nolint:gosec // mock refresh token in test
				RefreshToken: &OAuth2RefreshToken{
					TokenValue: "valid-server-refresh-token",
				},
			}
			saveErr := authService.Save(auth)
			Expect(saveErr).NotTo(HaveOccurred())

			tokenURI, parseErr := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(parseErr).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			handler.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			handler.SetFormValue("grant_type", "refresh_token")
			handler.SetFormValue("refresh_token", "valid-server-refresh-token")

			execErr := router.Execute(handler)
			Expect(execErr).NotTo(HaveOccurred())

			var resp map[string]any
			jsonErr := json.Unmarshal(handler.Res.Body.Bytes(), &resp)
			Expect(jsonErr).NotTo(HaveOccurred())
			Expect(resp).To(HaveKey("access_token"))
		})

		It("returns error when client_id is invalid or grant_type is unknown", func() {
			tokenURI, parseErr := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(parseErr).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			handler.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("non-existent-client:sec")))
			handler.SetFormValue("grant_type", "client_credentials")

			execErr := router.Execute(handler)
			Expect(execErr).To(HaveOccurred())
			defaultEx := &DefaultSecurityFilterChainException{}
			ok := errors.As(execErr, &defaultEx)
			Expect(ok).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(400))
		})

		It("returns 500 when randRead fails generating authorization code", func() {
			authUser := DefaultOAuth2User{}.New(
				[]GrantedAuthority{Authority("ROLE_USER")},
				map[string]any{"sub": "john_doe"},
				"sub",
			)
			contextHolder.GetContext().SetAuthentication(
				OAuth2AuthenticationToken{}.New(authUser, authUser.GetAuthorities(), "internal"),
			)

			reset := SetRandReadForTest(func([]byte) (int, error) {
				return 0, errors.New("simulated rand failure")
			})
			defer reset()

			authURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize" +
				"?response_type=code" +
				"&client_id=my-spa-app" +
				"&redirect_uri=" + url.QueryEscape("https://my-spa.example.com/callback") +
				"&code_challenge=challenge123" +
				"&code_challenge_method=S256")
			Expect(err).NotTo(HaveOccurred())

			handler := NewMockSecurityHandler(HttpMethods.GET, authURI)
			execErr := router.Execute(handler)
			Expect(execErr).To(HaveOccurred())
			var defaultEx *DefaultSecurityFilterChainException
			Expect(errors.As(execErr, &defaultEx)).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(http.StatusInternalServerError))
		})

		It("returns 500 when randRead fails generating authorization ID in authorize", func() {
			authUser := DefaultOAuth2User{}.New(
				[]GrantedAuthority{Authority("ROLE_USER")},
				map[string]any{"sub": "john_doe"},
				"sub",
			)
			contextHolder.GetContext().SetAuthentication(
				OAuth2AuthenticationToken{}.New(authUser, authUser.GetAuthorities(), "internal"),
			)

			calls := 0
			reset := SetRandReadForTest(func(b []byte) (int, error) {
				calls++
				if calls == 1 {
					return len(b), nil
				}
				return 0, errors.New("simulated auth id rand failure")
			})
			defer reset()

			authURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize" +
				"?response_type=code" +
				"&client_id=my-spa-app" +
				"&redirect_uri=" + url.QueryEscape("https://my-spa.example.com/callback") +
				"&code_challenge=challenge123" +
				"&code_challenge_method=S256")
			Expect(err).NotTo(HaveOccurred())

			handler := NewMockSecurityHandler(HttpMethods.GET, authURI)
			execErr := router.Execute(handler)
			Expect(execErr).To(HaveOccurred())
			var defaultEx *DefaultSecurityFilterChainException
			Expect(errors.As(execErr, &defaultEx)).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(http.StatusInternalServerError))
		})

		It("returns server error when randRead fails generating authorization ID in client_credentials", func() {
			reset := SetRandReadForTest(func([]byte) (int, error) {
				return 0, errors.New("simulated client creds rand failure")
			})
			defer reset()

			tokenURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			handler.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			handler.SetFormValue("grant_type", "client_credentials")

			execErr := router.Execute(handler)
			Expect(execErr).To(HaveOccurred())
			var defaultEx *DefaultSecurityFilterChainException
			Expect(errors.As(execErr, &defaultEx)).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(http.StatusBadRequest))
		})

		It("handles sendTokenSuccess serialization and write errors", func() {
			tokenURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(err).NotTo(HaveOccurred())
			access := &OAuth2AccessToken{
				TokenValue: "at-val",
				TokenType:  TokenTypeBearer,
				ExpiresAt:  time.Now().Add(time.Hour),
				Scopes:     []string{"read"},
			}
			refresh := &OAuth2RefreshToken{
				TokenValue: "rt-val",
				ExpiresAt:  time.Now().Add(24 * time.Hour),
			}

			// Marshal failure
			resetMarshal := SetJsonMarshalForTest(func(any) ([]byte, error) {
				return nil, errors.New("simulated json marshal failure")
			})
			h1 := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			err1 := filter.SendTokenSuccessForTest(h1, access, refresh)
			resetMarshal()
			Expect(err1).To(HaveOccurred())
			var defaultEx *DefaultSecurityFilterChainException
			Expect(errors.As(err1, &defaultEx)).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(http.StatusBadRequest))

			// Write failure
			h2 := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			failingH := &testMockFailingWriteSecurityHandler{SecurityHandler: h2}
			err2 := filter.SendTokenSuccessForTest(failingH, access, refresh)
			Expect(err2).To(MatchError(ContainSubstring("simulated write error")))
		})
	})

	Context("Filter Lifecycle, Authenticate, and Constructors", func() {
		It("tests Authenticate and AuthenticationRequired", func() {
			u, err := url.Parse("https://auth.beamfoundry.com/any")
			Expect(err).NotTo(HaveOccurred())
			h := NewMockSecurityHandler(HttpMethods.GET, u)

			authEx := filter.Authenticate(h)
			Expect(authEx).To(HaveOccurred())
			Expect(authEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))

			reqEx := filter.AuthenticationRequired(h)
			Expect(reqEx).To(HaveOccurred())
			defaultEx, ok := reqEx.(*DefaultSecurityFilterChainException)
			Expect(ok).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(401))
		})

		It("tests filter constructors and WithContext lifecycle", func() {
			settingsDef := NewDefaultAuthorizationServerSettings("https://auth.example.com")
			Expect(settingsDef.Issuer).To(Equal("https://auth.example.com"))

			newFilter := NewOAuth2AuthorizationServerFilter(settingsDef, clientRepo, authService, generator, km, contextHolder)
			Expect(newFilter.Config()).NotTo(BeNil())
			Expect(newFilter.Config().Settings.Issuer).To(Equal("https://auth.example.com"))

			// Non-HttpSecurity context parent
			invalidCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, "not-http-sec")
			err := newFilter.WithContext(invalidCtx)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("IllegalArgumentException"))

			// Missing filter in HttpSecurity
			emptyBuilder := &HttpSecurityBuilder{}
			missingCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, emptyBuilder.Build())
			err = newFilter.WithContext(missingCtx)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("IllegalArgumentException"))

			// Invalid config type in HttpSecurity
			invalidBuilder := &HttpSecurityBuilder{}
			invalidBuilder.AddCustomSecurityFilter("oAuth2AuthorizationServerFilter", "invalid")
			invalidCfgCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, invalidBuilder.Build())
			err = newFilter.WithContext(invalidCfgCtx)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("IllegalArgumentException"))

			// Valid config in HttpSecurity
			validBuilder := &HttpSecurityBuilder{}
			validCfg := &OAuth2AuthorizationServerConfig{
				Settings:              settingsDef,
				ClientRepository:      clientRepo,
				AuthorizationService:  authService,
				TokenGenerator:        generator,
				JWKSource:             km,
				SecurityContextHolder: contextHolder,
			}
			validBuilder.AddCustomSecurityFilter("oAuth2AuthorizationServerFilter", validCfg)
			validCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, validBuilder.Build())
			err = newFilter.WithContext(validCtx)
			Expect(err).NotTo(HaveOccurred())

			// Background context
			fNoParent := &OAuth2AuthorizationServerFilter{}
			err = fNoParent.WithContext(context.Background())
			Expect(err).NotTo(HaveOccurred())
		})

		It("tests NewInMemoryRegisteredClientRepository, NewInMemoryOAuth2AuthorizationService, NewJwtOAuth2TokenGenerator", func() {
			repo := NewInMemoryRegisteredClientRepository(registeredClient)
			Expect(repo).NotTo(BeNil())

			service := NewInMemoryOAuth2AuthorizationService()
			Expect(service).NotTo(BeNil())

			encoder := NewDefaultJwtEncoder(km)
			gen := NewJwtOAuth2TokenGenerator(encoder, "https://auth.example.com")
			Expect(gen).NotTo(BeNil())
		})

		It("tests handleIntrospect for active and inactive tokens", func() {
			// Save active token authorization
			now := time.Now()
			at := NewOAuth2AccessToken(TokenTypeBearer, "introspect-at-val", now, now.Add(time.Hour), []string{"read", "write"})
			auth := &OAuth2Authorization{
				ID:                 "introspect-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-introspect",
				AuthorizedScopes:   []string{"read", "write"},
				AccessToken:        at,
			}
			Expect(authService.Save(auth)).NotTo(HaveOccurred())

			// 1. Introspect active token with valid client auth
			introspectURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/introspect")
			Expect(err).NotTo(HaveOccurred())
			hActive := NewMockSecurityHandler(HttpMethods.POST, introspectURI)
			hActive.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hActive.SetFormValue("token", "introspect-at-val")

			Expect(router.Execute(hActive)).To(Succeed())
			var activeResp map[string]any
			Expect(json.Unmarshal(hActive.Res.Body.Bytes(), &activeResp)).To(Succeed())
			Expect(activeResp).To(HaveKeyWithValue("active", true))
			Expect(activeResp).To(HaveKeyWithValue("sub", "user-introspect"))
			Expect(activeResp).To(HaveKeyWithValue("client_id", registeredClient.ClientID))

			// 2. Introspect unknown/inactive token
			hInactive := NewMockSecurityHandler(HttpMethods.POST, introspectURI)
			hInactive.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hInactive.SetFormValue("token", "unknown-token")
			Expect(router.Execute(hInactive)).To(Succeed())
			var inactiveResp map[string]any
			Expect(json.Unmarshal(hInactive.Res.Body.Bytes(), &inactiveResp)).To(Succeed())
			Expect(inactiveResp).To(HaveKeyWithValue("active", false))

			// 3. Introspect with invalid client credentials fails
			hBadClient := NewMockSecurityHandler(HttpMethods.POST, introspectURI)
			hBadClient.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:wrong-secret")))
			hBadClient.SetFormValue("token", "introspect-at-val")
			Expect(router.Execute(hBadClient)).To(HaveOccurred())
		})

		It("tests handleRevoke for access token, client authorization check, and unknown token", func() {
			revokeURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/revoke")
			Expect(err).NotTo(HaveOccurred())

			// 1. Revoke access token with valid client credentials
			now := time.Now()
			at := NewOAuth2AccessToken(TokenTypeBearer, "revoke-at-val", now, now.Add(time.Hour), []string{"read"})
			auth := &OAuth2Authorization{
				ID:                 "revoke-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-revoke",
				AccessToken:        at,
			}
			Expect(authService.Save(auth)).NotTo(HaveOccurred())

			hRevoke := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevoke.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRevoke.SetFormValue("token", "revoke-at-val")
			Expect(router.Execute(hRevoke)).To(Succeed())
			Expect(hRevoke.Res.Body.String()).To(Equal("{}"))

			// 2. Revoke unknown token (RFC 7009 returns 200 OK)
			hRevokeUnknown := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevokeUnknown.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRevokeUnknown.SetFormValue("token", "not-found-token")
			Expect(router.Execute(hRevokeUnknown)).To(Succeed())
			Expect(hRevokeUnknown.Res.Body.String()).To(Equal("{}"))

			// 3. Revoke with invalid client credentials fails
			hRevokeBad := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevokeBad.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:wrong-secret")))
			hRevokeBad.SetFormValue("token", "not-found-token")
			Expect(router.Execute(hRevokeBad)).To(HaveOccurred())

			// 4. Revoke returns 500 when FindByToken fails with storage error
			failingAuthSvc := &testMockFailingAuthorizationService{
				OAuth2AuthorizationService: authService,
				failFindByToken:            true,
			}
			filterFailing := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, failingAuthSvc, generator, km, contextHolder)
			routerFailing := NewMockSecurityRouter()
			filterFailing.RegisterSecurityEndpoint(routerFailing)

			hRevokeFindFail := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevokeFindFail.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRevokeFindFail.SetFormValue("token", "revoke-at-val")
			Expect(routerFailing.Execute(hRevokeFindFail)).To(HaveOccurred())

			// 5. Revoke returns 500 when Remove fails
			failingAuthSvcRemove := &testMockFailingAuthorizationService{
				OAuth2AuthorizationService: authService,
				failRemove:                 true,
			}
			filterFailingRemove := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, failingAuthSvcRemove, generator, km, contextHolder)
			routerFailingRemove := NewMockSecurityRouter()
			filterFailingRemove.RegisterSecurityEndpoint(routerFailingRemove)

			atRm := NewOAuth2AccessToken(TokenTypeBearer, "revoke-rm-fail-val", now, now.Add(time.Hour), []string{"read"})
			authRm := &OAuth2Authorization{
				ID:                 "revoke-rm-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-revoke",
				AccessToken:        atRm,
			}
			Expect(authService.Save(authRm)).NotTo(HaveOccurred())

			hRevokeRmFail := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevokeRmFail.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRevokeRmFail.SetFormValue("token", "revoke-rm-fail-val")
			Expect(routerFailingRemove.Execute(hRevokeRmFail)).To(HaveOccurred())

			// 6. Token endpoint returns server_error when Save fails on authorization_code grant
			tokenURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(err).NotTo(HaveOccurred())

			failingAuthSvcSave := &testMockFailingAuthorizationService{
				OAuth2AuthorizationService: authService,
				failSave:                   true,
			}
			filterFailingSave := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, failingAuthSvcSave, generator, km, contextHolder)
			routerFailingSave := NewMockSecurityRouter()
			filterFailingSave.RegisterSecurityEndpoint(routerFailingSave)

			authCodeToSave := &OAuth2Authorization{
				ID:                 "code-save-fail-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-save-fail",
				AuthorizationCode: &AuthorizationCode{
					Value:               "code-save-fail",
					IssuedAt:            time.Now(),
					ExpiresAt:           time.Now().Add(5 * time.Minute),
					RedirectURI:         registeredClient.RedirectURIs[0],
					CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
					CodeChallengeMethod: "S256",
				},
			}
			Expect(authService.Save(authCodeToSave)).NotTo(HaveOccurred())

			hAuthCodeSaveFail := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hAuthCodeSaveFail.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hAuthCodeSaveFail.SetFormValue("grant_type", "authorization_code")
			hAuthCodeSaveFail.SetFormValue("code", "code-save-fail")
			hAuthCodeSaveFail.SetFormValue("redirect_uri", registeredClient.RedirectURIs[0])
			hAuthCodeSaveFail.SetFormValue("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
			Expect(routerFailingSave.Execute(hAuthCodeSaveFail)).To(HaveOccurred())
			var saveFailResp map[string]any
			Expect(json.Unmarshal(hAuthCodeSaveFail.Res.Body.Bytes(), &saveFailResp)).To(Succeed())
			Expect(saveFailResp["error"]).To(Equal(OAuth2ErrorServerError))

			// 7. Token endpoint returns server_error when Save fails on client_credentials grant
			hCCSaveFail := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hCCSaveFail.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hCCSaveFail.SetFormValue("grant_type", "client_credentials")
			Expect(routerFailingSave.Execute(hCCSaveFail)).To(HaveOccurred())
			var ccSaveFailResp map[string]any
			Expect(json.Unmarshal(hCCSaveFail.Res.Body.Bytes(), &ccSaveFailResp)).To(Succeed())
			Expect(ccSaveFailResp["error"]).To(Equal(OAuth2ErrorServerError))
		})

		It("tests handleAuthorize and handleToken validation error branches", func() {
			// 1. handleAuthorize unknown client_id
			authURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize?client_id=unknown-client&response_type=code")
			Expect(err).NotTo(HaveOccurred())
			hAuthBadClient := NewMockSecurityHandler(HttpMethods.GET, authURI)
			ex := router.Execute(hAuthBadClient)
			Expect(ex).To(HaveOccurred())

			// 2. handleAuthorize unsupported response_type
			authURI2, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize?client_id=my-spa-app&response_type=token")
			Expect(err).NotTo(HaveOccurred())
			hAuthBadType := NewMockSecurityHandler(HttpMethods.GET, authURI2)
			ex = router.Execute(hAuthBadType)
			Expect(ex).To(HaveOccurred())

			// 3. handleAuthorize PKCE required but missing code_challenge
			authURIPkce, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize?client_id=my-spa-app&response_type=code")
			Expect(err).NotTo(HaveOccurred())
			hAuthNoPkce := NewMockSecurityHandler(HttpMethods.GET, authURIPkce)
			ex = router.Execute(hAuthNoPkce)
			Expect(ex).To(HaveOccurred())

			// 4. handleToken wrong client secret
			tokenURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(err).NotTo(HaveOccurred())
			hBadSec := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hBadSec.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:wrong-secret")))
			hBadSec.SetFormValue("grant_type", "authorization_code")
			ex = router.Execute(hBadSec)
			Expect(ex).To(HaveOccurred())

			// 5. handleToken code grant with PKCE verifier mismatch
			pkceAuth := &OAuth2Authorization{
				ID:                 "pkce-auth-err",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-pkce",
				AuthorizationCode: &AuthorizationCode{
					Value:               "pkce-code-val",
					IssuedAt:            time.Now(),
					ExpiresAt:           time.Now().Add(5 * time.Minute),
					CodeChallenge:       "actual-challenge",
					CodeChallengeMethod: "S256",
					RedirectURI:         "https://my.app/callback",
				},
			}
			Expect(authService.Save(pkceAuth)).NotTo(HaveOccurred())

			hPkceMismatch := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hPkceMismatch.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hPkceMismatch.SetFormValue("grant_type", "authorization_code")
			hPkceMismatch.SetFormValue("code", "pkce-code-val")
			hPkceMismatch.SetFormValue("redirect_uri", "https://my.app/callback")
			hPkceMismatch.SetFormValue("code_verifier", "wrong-verifier")
			ex = router.Execute(hPkceMismatch)
			Expect(ex).To(HaveOccurred())

			// 6. Authorization code already invalidated (code re-use)
			invalidatedAuth := &OAuth2Authorization{
				ID:                 "reused-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-reuse",
				AuthorizationCode: &AuthorizationCode{
					Value:       "reused-code",
					IssuedAt:    time.Now().Add(-1 * time.Minute),
					ExpiresAt:   time.Now().Add(4 * time.Minute),
					Invalidated: true,
				},
			}
			Expect(authService.Save(invalidatedAuth)).NotTo(HaveOccurred())
			hReuse := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hReuse.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hReuse.SetFormValue("grant_type", "authorization_code")
			hReuse.SetFormValue("code", "reused-code")
			Expect(router.Execute(hReuse)).To(HaveOccurred())

			// 7. Authorization code expired
			expiredCodeAuth := &OAuth2Authorization{
				ID:                 "expired-code-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-expired",
				AuthorizationCode: &AuthorizationCode{
					Value:     "expired-code",
					IssuedAt:  time.Now().Add(-10 * time.Minute),
					ExpiresAt: time.Now().Add(-5 * time.Minute),
				},
			}
			Expect(authService.Save(expiredCodeAuth)).NotTo(HaveOccurred())
			hExpired := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hExpired.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hExpired.SetFormValue("grant_type", "authorization_code")
			hExpired.SetFormValue("code", "expired-code")
			Expect(router.Execute(hExpired)).To(HaveOccurred())

			// 8. Redirect URI mismatch
			mismatchURIAuth := &OAuth2Authorization{
				ID:                 "uri-mismatch-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-uri",
				AuthorizationCode: &AuthorizationCode{
					Value:       "uri-code",
					IssuedAt:    time.Now(),
					ExpiresAt:   time.Now().Add(5 * time.Minute),
					RedirectURI: "https://expected.com/cb",
				},
			}
			Expect(authService.Save(mismatchURIAuth)).NotTo(HaveOccurred())
			hMismatchURI := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hMismatchURI.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hMismatchURI.SetFormValue("grant_type", "authorization_code")
			hMismatchURI.SetFormValue("code", "uri-code")
			hMismatchURI.SetFormValue("redirect_uri", "https://different.com/cb")
			Expect(router.Execute(hMismatchURI)).To(HaveOccurred())

			// 9. Token request with form post credentials (no Basic Auth header)
			hFormPost := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hFormPost.SetFormValue("client_id", "my-spa-app")
			hFormPost.SetFormValue("client_secret", "client-secret-123")
			hFormPost.SetFormValue("grant_type", "client_credentials")
			Expect(router.Execute(hFormPost)).To(Succeed())

			// 10. RegisteredClientRepository.FindByID error
			_, findErr := clientRepo.FindByID("non-existent-id")
			Expect(findErr).To(HaveOccurred())

			// 11. Refresh Token Grant (valid and invalid)
			rfAuth := &OAuth2Authorization{
				ID:                 "rf-auth-id",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-rf",
				//nolint:gosec // test refresh token
				RefreshToken: &OAuth2RefreshToken{
					TokenValue: "rf-token-valid",
					IssuedAt:   time.Now(),
				},
			}
			Expect(authService.Save(rfAuth)).NotTo(HaveOccurred())

			// Valid refresh token
			hRFValid := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hRFValid.SetFormValue("client_id", "my-spa-app")
			hRFValid.SetFormValue("client_secret", "client-secret-123")
			hRFValid.SetFormValue("grant_type", "refresh_token")
			hRFValid.SetFormValue("refresh_token", "rf-token-valid")
			Expect(router.Execute(hRFValid)).To(Succeed())

			// Invalid refresh token
			hRFInvalid := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hRFInvalid.SetFormValue("client_id", "my-spa-app")
			hRFInvalid.SetFormValue("client_secret", "client-secret-123")
			hRFInvalid.SetFormValue("grant_type", "refresh_token")
			hRFInvalid.SetFormValue("refresh_token", "rf-token-unknown")
			Expect(router.Execute(hRFInvalid)).To(HaveOccurred())

			// 12. Client without client_credentials grant type
			noCCClient := &RegisteredClient{
				ID:                      "client-no-cc",
				ClientID:                "no-cc-app",
				ClientSecret:            "no-cc-secret",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeAuthorizationCode},
			}
			repoWithNoCC := NewInMemoryRegisteredClientRepository(registeredClient, noCCClient)
			filterNoCC := OAuth2AuthorizationServerFilter{}.New(
				settings,
				repoWithNoCC,
				authService,
				generator,
				km,
				contextHolder,
			)
			routerNoCC := NewMockSecurityRouter()
			filterNoCC.RegisterSecurityEndpoint(routerNoCC)

			hNoCC := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hNoCC.SetFormValue("client_id", "no-cc-app")
			hNoCC.SetFormValue("client_secret", "no-cc-secret")
			hNoCC.SetFormValue("grant_type", "client_credentials")
			Expect(routerNoCC.Execute(hNoCC)).To(HaveOccurred())

			// 13. Token request without client authentication (401 invalid_client)
			hNoAuth := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hNoAuth.SetFormValue("grant_type", "client_credentials")
			Expect(router.Execute(hNoAuth)).To(HaveOccurred())

			// 14. Token request with unsupported grant type
			hUnsupportedGrant := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hUnsupportedGrant.SetFormValue("client_id", "my-spa-app")
			hUnsupportedGrant.SetFormValue("client_secret", "client-secret-123")
			hUnsupportedGrant.SetFormValue("grant_type", "password")
			Expect(router.Execute(hUnsupportedGrant)).To(HaveOccurred())

			// 15. Discovery endpoint: /.well-known/oauth-authorization-server
			oauthDiscURI, err := url.Parse("https://auth.beamfoundry.com/.well-known/oauth-authorization-server")
			Expect(err).NotTo(HaveOccurred())
			hOAuthDisc := NewMockSecurityHandler(HttpMethods.GET, oauthDiscURI)
			Expect(router.Execute(hOAuthDisc)).To(Succeed())

			// 16. Injected dependencies in OAuth2AuthorizationServerFilter
			fWithInjected := &OAuth2AuthorizationServerFilter{}
			fWithInjected.SetInjectedDepsForTest(
				clientRepo,
				contextHolder,
				km,
				generator,
				authService,
				settings,
			)
			validSec := (&HttpSecurityBuilder{}).AddCustomSecurityFilter("oAuth2AuthorizationServerFilter", &OAuth2AuthorizationServerConfig{}).Build()
			validCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, validSec)
			Expect(fWithInjected.WithContext(validCtx)).To(Succeed())
			deps := fWithInjected.GetDepsForTest()
			Expect(deps.ClientRepo).NotTo(BeNil())
			Expect(deps.ContextHolder).NotTo(BeNil())
			Expect(deps.JWKSource).NotTo(BeNil())
			Expect(deps.TokenGenerator).NotTo(BeNil())
			Expect(deps.AuthService).NotTo(BeNil())
			Expect(deps.Settings).NotTo(BeNil())
			// 17. Unauthenticated user on handleAuthorize redirects to /login
			contextHolder.GetContext().SetAuthentication(nil)
			authURI, err = url.Parse("https://auth.beamfoundry.com/oauth2/authorize?client_id=my-spa-app&response_type=code&redirect_uri=https://my-spa.example.com/callback&code_challenge=xyz&code_challenge_method=S256")
			Expect(err).NotTo(HaveOccurred())
			hUnauth := NewMockSecurityHandler(HttpMethods.GET, authURI)
			unauthEx := router.Execute(hUnauth)
			Expect(unauthEx).To(HaveOccurred())
			var secEx SecurityFilterChainException
			Expect(errors.As(unauthEx, &secEx)).To(BeTrue())
			Expect(secEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))

			// 18. Failing JWKS source returns 500
			failingSource := &testMockFailingJWKSource{}
			filterFailingJWK := OAuth2AuthorizationServerFilter{}.New(
				settings,
				clientRepo,
				authService,
				generator,
				failingSource,
				contextHolder,
			)
			routerFailingJWK := NewMockSecurityRouter()
			filterFailingJWK.RegisterSecurityEndpoint(routerFailingJWK)
			jwksURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/jwks")
			Expect(err).NotTo(HaveOccurred())
			hFailingJWK := NewMockSecurityHandler(HttpMethods.GET, jwksURI)
			Expect(routerFailingJWK.Execute(hFailingJWK)).To(HaveOccurred())

			// 19. Public client rejected on client_credentials grant
			publicClient := &RegisteredClient{
				ID:                          "public-client-id",
				ClientID:                    "public-app",
				ClientName:                  "Public App",
				ClientAuthenticationMethods: []ClientAuthenticationMethod{ClientAuthMethodNone},
				AuthorizationGrantTypes:     []AuthorizationGrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken, GrantTypeClientCredentials},
				RedirectURIs:                []string{"https://public.example.com/callback"},
				Scopes:                      []string{"openid", "profile"},
				RequireProofKey:             true,
			}
			Expect(clientRepo.Save(publicClient)).NotTo(HaveOccurred())

			hPublicCC := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hPublicCC.SetFormValue("client_id", "public-app")
			hPublicCC.SetFormValue("grant_type", "client_credentials")
			Expect(router.Execute(hPublicCC)).To(HaveOccurred())

			// 20. Scope validation in handleAuthorize: unauthorized scope rejected
			authUser := DefaultOAuth2User{}.New([]GrantedAuthority{Authority("ROLE_USER")}, map[string]any{"sub": "john"}, "sub")
			contextHolder.GetContext().SetAuthentication(OAuth2AuthenticationToken{}.New(authUser, authUser.GetAuthorities(), "internal"))
			authBadScopeURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize?client_id=my-spa-app&response_type=code&scope=unauthorized-scope&redirect_uri=" + url.QueryEscape("https://my-spa.example.com/callback") + "&code_challenge=xyz&code_challenge_method=S256")
			Expect(err).NotTo(HaveOccurred())
			hBadScope := NewMockSecurityHandler(HttpMethods.GET, authBadScopeURI)
			Expect(router.Execute(hBadScope)).To(HaveOccurred())

			// 21. handleAuthorize missing redirect_uri with multiple registered redirect URIs rejected
			multiRedirectClient := &RegisteredClient{
				ID:                      "multi-uri-client",
				ClientID:                "multi-uri-app",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeAuthorizationCode},
				RedirectURIs:            []string{"https://app1.example.com/cb", "https://app2.example.com/cb"},
				Scopes:                  []string{"read"},
			}
			Expect(clientRepo.Save(multiRedirectClient)).NotTo(HaveOccurred())
			authMissingURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize?client_id=multi-uri-app&response_type=code")
			Expect(err).NotTo(HaveOccurred())
			hMissingURI := NewMockSecurityHandler(HttpMethods.GET, authMissingURI)
			Expect(router.Execute(hMissingURI)).To(HaveOccurred())

			// 22. handleAuthorize client not registered for authorization_code grant rejected
			noAuthCodeClient := &RegisteredClient{
				ID:                      "no-auth-code-client",
				ClientID:                "no-auth-code-app",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeClientCredentials},
				RedirectURIs:            []string{"https://app.example.com/cb"},
			}
			Expect(clientRepo.Save(noAuthCodeClient)).NotTo(HaveOccurred())
			authNoCodeGrantURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize?client_id=no-auth-code-app&response_type=code&redirect_uri=" + url.QueryEscape("https://app.example.com/cb"))
			Expect(err).NotTo(HaveOccurred())
			hNoCodeGrant := NewMockSecurityHandler(HttpMethods.GET, authNoCodeGrantURI)
			Expect(router.Execute(hNoCodeGrant)).To(HaveOccurred())

			// 23. handleAuthorizationCodeGrant with wrong client ID rejected
			diffClientAuth := &OAuth2Authorization{
				ID:                 "diff-client-auth",
				RegisteredClientID: "other-client-id",
				PrincipalName:      "user-diff",
				AuthorizationCode: &AuthorizationCode{
					Value:       "diff-code",
					IssuedAt:    time.Now(),
					ExpiresAt:   time.Now().Add(5 * time.Minute),
					RedirectURI: "https://my-spa.example.com/callback",
				},
			}
			Expect(authService.Save(diffClientAuth)).NotTo(HaveOccurred())
			hDiffClient := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hDiffClient.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hDiffClient.SetFormValue("grant_type", "authorization_code")
			hDiffClient.SetFormValue("code", "diff-code")
			hDiffClient.SetFormValue("redirect_uri", "https://my-spa.example.com/callback")
			Expect(router.Execute(hDiffClient)).To(HaveOccurred())

			// 24. handleRefreshTokenGrant with expired refresh token rejected
			expiredRFAuth := &OAuth2Authorization{
				ID:                 "expired-rf-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-rf-expired",
				RefreshToken: &OAuth2RefreshToken{
					TokenValue: "expired-rf-val", // #nosec G101
					IssuedAt:   time.Now().Add(-2 * time.Hour),
					ExpiresAt:  time.Now().Add(-1 * time.Hour),
				},
			}
			Expect(authService.Save(expiredRFAuth)).NotTo(HaveOccurred())
			hExpiredRF := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hExpiredRF.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hExpiredRF.SetFormValue("grant_type", "refresh_token")
			hExpiredRF.SetFormValue("refresh_token", "expired-rf-val")
			Expect(router.Execute(hExpiredRF)).To(HaveOccurred())

			// 25. handleRefreshTokenGrant with wrong client ID rejected
			diffClientRFAuth := &OAuth2Authorization{
				ID:                 "diff-rf-auth",
				RegisteredClientID: "other-client-id",
				PrincipalName:      "user-diff-rf",
				RefreshToken: &OAuth2RefreshToken{
					TokenValue: "diff-client-rf-val", // #nosec G101
					IssuedAt:   time.Now(),
					ExpiresAt:  time.Now().Add(time.Hour),
				},
			}
			Expect(authService.Save(diffClientRFAuth)).NotTo(HaveOccurred())
			hDiffRF := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hDiffRF.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hDiffRF.SetFormValue("grant_type", "refresh_token")
			hDiffRF.SetFormValue("refresh_token", "diff-client-rf-val")
			Expect(router.Execute(hDiffRF)).To(HaveOccurred())

			// 26. handleRevoke does not remove token owned by another client
			foreignToken := NewOAuth2AccessToken(TokenTypeBearer, "foreign-at", time.Now(), time.Now().Add(time.Hour), []string{"read"})
			foreignAuth := &OAuth2Authorization{
				ID:                 "foreign-auth",
				RegisteredClientID: "different-owner-id",
				AccessToken:        foreignToken,
			}
			Expect(authService.Save(foreignAuth)).NotTo(HaveOccurred())
			revokeURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/revoke")
			Expect(err).NotTo(HaveOccurred())
			hRevokeForeign := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevokeForeign.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRevokeForeign.SetFormValue("token", "foreign-at")
			Expect(router.Execute(hRevokeForeign)).To(Succeed())
			// Must still exist in authorization service
			stillThere, findErr := authService.FindByToken("foreign-at", "access_token")
			Expect(findErr).NotTo(HaveOccurred())
			Expect(stillThere.ID).To(Equal("foreign-auth"))

			// 27a. Mismatch at /token is rejected
			codeOmittedURIAuth := &OAuth2Authorization{
				ID:                 "omitted-uri-auth-1",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-omitted-uri",
				AuthorizationCode: &AuthorizationCode{
					Value:               "code-omitted-uri-1",
					IssuedAt:            time.Now(),
					ExpiresAt:           time.Now().Add(5 * time.Minute),
					RedirectURI:         registeredClient.RedirectURIs[0],
					RedirectURISupplied: false,
				},
			}
			Expect(authService.Save(codeOmittedURIAuth)).NotTo(HaveOccurred())
			hTokenMismatch := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hTokenMismatch.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hTokenMismatch.SetFormValue("grant_type", "authorization_code")
			hTokenMismatch.SetFormValue("code", "code-omitted-uri-1")
			hTokenMismatch.SetFormValue("redirect_uri", "https://other.example.com/wrong")
			Expect(router.Execute(hTokenMismatch)).To(HaveOccurred())

			// 27b. Omission at /token is accepted
			codeOmittedURIAuth2 := &OAuth2Authorization{
				ID:                 "omitted-uri-auth-2",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-omitted-uri-2",
				AuthorizationCode: &AuthorizationCode{
					Value:               "code-omitted-uri-2",
					IssuedAt:            time.Now(),
					ExpiresAt:           time.Now().Add(5 * time.Minute),
					RedirectURI:         registeredClient.RedirectURIs[0],
					RedirectURISupplied: false,
				},
			}
			Expect(authService.Save(codeOmittedURIAuth2)).NotTo(HaveOccurred())
			hTokenOmitted := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hTokenOmitted.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hTokenOmitted.SetFormValue("grant_type", "authorization_code")
			hTokenOmitted.SetFormValue("code", "code-omitted-uri-2")
			Expect(router.Execute(hTokenOmitted)).To(Succeed())

			// 28. redirect_uri supplied at /authorize requires exact match at /token (rejects omission)
			codeSuppliedURIAuth := &OAuth2Authorization{
				ID:                 "supplied-uri-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-supplied-uri",
				AuthorizationCode: &AuthorizationCode{
					Value:               "code-supplied-uri",
					IssuedAt:            time.Now(),
					ExpiresAt:           time.Now().Add(5 * time.Minute),
					RedirectURI:         registeredClient.RedirectURIs[0],
					RedirectURISupplied: true,
				},
			}
			Expect(authService.Save(codeSuppliedURIAuth)).NotTo(HaveOccurred())

			// 28a. Omission at /token rejected when supplied at /authorize
			hTokenOmitWhenSupplied := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hTokenOmitWhenSupplied.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hTokenOmitWhenSupplied.SetFormValue("grant_type", "authorization_code")
			hTokenOmitWhenSupplied.SetFormValue("code", "code-supplied-uri")
			Expect(router.Execute(hTokenOmitWhenSupplied)).To(HaveOccurred())

			// 28b. Exact match accepted
			codeSuppliedURIAuth2 := &OAuth2Authorization{
				ID:                 "supplied-uri-auth-2",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-supplied-uri-2",
				AuthorizationCode: &AuthorizationCode{
					Value:               "code-supplied-uri-2",
					IssuedAt:            time.Now(),
					ExpiresAt:           time.Now().Add(5 * time.Minute),
					RedirectURI:         registeredClient.RedirectURIs[0],
					RedirectURISupplied: true,
				},
			}
			Expect(authService.Save(codeSuppliedURIAuth2)).NotTo(HaveOccurred())
			hTokenExactMatch := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hTokenExactMatch.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hTokenExactMatch.SetFormValue("grant_type", "authorization_code")
			hTokenExactMatch.SetFormValue("code", "code-supplied-uri-2")
			hTokenExactMatch.SetFormValue("redirect_uri", registeredClient.RedirectURIs[0])
			Expect(router.Execute(hTokenExactMatch)).To(Succeed())
		})

		It("tests InvalidateAuthorizationCode, SaveTokens, and untracked Remove in InMemoryOAuth2AuthorizationService", func() {
			service := InMemoryOAuth2AuthorizationService{}.New()

			// 1. InvalidateAuthorizationCode with nil AuthorizationCode
			authNilCode := &OAuth2Authorization{
				ID: "auth-nil-code",
			}
			service.SetAuthCodeForTest("nil-code", authNilCode)
			_, err := service.InvalidateAuthorizationCode("nil-code")
			Expect(err).To(HaveOccurred())

			// 2. InvalidateAuthorizationCode already used
			authUsedCode := &OAuth2Authorization{
				ID: "auth-used-code",
				AuthorizationCode: &AuthorizationCode{
					Value:       "used-code",
					Invalidated: true,
					ExpiresAt:   time.Now().Add(5 * time.Minute),
				},
			}
			Expect(service.Save(authUsedCode)).NotTo(HaveOccurred())
			_, err = service.InvalidateAuthorizationCode("used-code")
			Expect(err).To(HaveOccurred())

			// 3. InvalidateAuthorizationCode expired
			authExpiredCode := &OAuth2Authorization{
				ID: "auth-expired-code",
				AuthorizationCode: &AuthorizationCode{
					Value:       "expired-code",
					Invalidated: false,
					ExpiresAt:   time.Now().Add(-5 * time.Minute),
				},
			}
			Expect(service.Save(authExpiredCode)).NotTo(HaveOccurred())
			_, err = service.InvalidateAuthorizationCode("expired-code")
			Expect(err).To(HaveOccurred())

			// 4. SaveTokens unknown ID
			at := NewOAuth2AccessToken(TokenTypeBearer, "at-val", time.Now(), time.Now().Add(time.Hour), []string{"read"})
			rt := NewOAuth2RefreshToken("rt-val", time.Now(), time.Now().Add(24*time.Hour))
			err = service.SaveTokens("non-existent-auth-id", "", at, rt)
			Expect(err).To(HaveOccurred())

			// 5. SaveTokens expected old refresh token but auth has nil refresh token
			authNoRT := &OAuth2Authorization{
				ID: "auth-no-rt",
			}
			Expect(service.Save(authNoRT)).NotTo(HaveOccurred())
			err = service.SaveTokens("auth-no-rt", "expected-rt", at, rt)
			Expect(err).To(HaveOccurred())

			// 6. SaveTokens expected old refresh token mismatch
			authWithRT := &OAuth2Authorization{
				ID:           "auth-with-rt",
				RefreshToken: NewOAuth2RefreshToken("actual-rt", time.Now(), time.Now().Add(24*time.Hour)),
			}
			Expect(service.Save(authWithRT)).NotTo(HaveOccurred())
			err = service.SaveTokens("auth-with-rt", "different-expected-rt", at, rt)
			Expect(err).To(HaveOccurred())

			// 7. Remove with untracked authorization (has tokens directly)
			authDirect := &OAuth2Authorization{
				ID: "auth-direct",
				AuthorizationCode: &AuthorizationCode{
					Value: "direct-code",
				},
				AccessToken:  at,
				RefreshToken: rt,
			}
			Expect(service.Save(authDirect)).NotTo(HaveOccurred())
			service.UntrackForTest(authDirect.ID)
			Expect(service.Remove(authDirect)).NotTo(HaveOccurred())
		})

		It("tests JwtOAuth2TokenGenerator encoder error and default refresh token TTL", func() {
			failingEncoder := &testMockFailingJwtEncoder{}
			gen := JwtOAuth2TokenGenerator{}.New(failingEncoder, "https://issuer.example.com")
			client := &RegisteredClient{
				ID:                      "client-id",
				ClientID:                "client-1",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeRefreshToken},
				RefreshTokenTimeToLive:  0, // triggers default 30 days
			}
			auth := &OAuth2Authorization{
				ID:            "auth-id",
				PrincipalName: "user1",
			}
			_, _, err := gen.Generate(auth, client)
			Expect(err).To(HaveOccurred())

			// Success with default refresh token TTL
			validGen := JwtOAuth2TokenGenerator{}.New(NewDefaultJwtEncoder(km), "https://issuer.example.com")
			at, rt, err := validGen.Generate(auth, client)
			Expect(err).NotTo(HaveOccurred())
			Expect(at).NotTo(BeNil())
			Expect(rt).NotTo(BeNil())
			Expect(rt.ExpiresAt).To(BeTemporally("~", time.Now().Add(30*24*time.Hour), 5*time.Second))
		})

		It("tests OAuth2AuthorizationServerFilter WithContext error cases and defaults", func() {
			filter := &OAuth2AuthorizationServerFilter{}

			// 1. Parent context value is not HttpSecurity
			ctxWrongParent := context.WithValue(context.Background(), PrototypeContextParentInstance, "not-http-sec")
			err := filter.WithContext(ctxWrongParent)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("IllegalArgumentException"))

			// 2. Parent HttpSecurity does not configure oAuth2AuthorizationServerFilter
			httpSec := &HttpSecurity{}
			ctxNoFilter := context.WithValue(context.Background(), PrototypeContextParentInstance, httpSec)
			err = filter.WithContext(ctxNoFilter)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("IllegalArgumentException"))

			// 3. Injected dependencies and default settings/generator
			filterInjected := &OAuth2AuthorizationServerFilter{}
			filterInjected.SetInjectedDepsForTest(clientRepo, contextHolder, km, nil, authService, nil)
			err = filterInjected.WithContext(context.Background())
			Expect(err).NotTo(HaveOccurred())
			deps := filterInjected.GetDepsForTest()
			Expect(deps.Settings).NotTo(BeNil())
			Expect(deps.Settings.Issuer).To(Equal("http://localhost:8080"))
			Expect(deps.TokenGenerator).NotTo(BeNil())
		})

		It("tests handleAuthorize scope validation, non-S256 PKCE, redirect_uri defaults, and unauthorized grant", func() {
			authURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/authorize")
			Expect(err).NotTo(HaveOccurred())

			// 1. Client not authorized for authorization_code grant
			ccOnlyClient := &RegisteredClient{
				ID:                      "cc-only-id",
				ClientID:                "cc-only-client",
				ClientSecret:            "secret",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeClientCredentials},
				RedirectURIs:            []string{"https://app.example.com/cb"},
				Scopes:                  []string{"read"},
			}
			Expect(clientRepo.Save(ccOnlyClient)).NotTo(HaveOccurred())

			hNoAuthCode := NewMockSecurityHandler(HttpMethods.GET, authURI)
			hNoAuthCode.URL().RawQuery = "client_id=cc-only-client&response_type=code"
			Expect(router.Execute(hNoAuthCode)).To(HaveOccurred())

			// 2. Missing redirect_uri when client has multiple registered URIs
			multiURIClient := &RegisteredClient{
				ID:                      "multi-uri-id",
				ClientID:                "multi-uri-client",
				ClientSecret:            "secret",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeAuthorizationCode},
				RedirectURIs:            []string{"https://app.example.com/cb1", "https://app.example.com/cb2"},
				Scopes:                  []string{"read"},
			}
			Expect(clientRepo.Save(multiURIClient)).NotTo(HaveOccurred())

			hMultiNoURI := NewMockSecurityHandler(HttpMethods.GET, authURI)
			hMultiNoURI.URL().RawQuery = "client_id=multi-uri-client&response_type=code"
			Expect(router.Execute(hMultiNoURI)).To(HaveOccurred())

			// 3. Invalid redirect_uri (not in registered URIs)
			hInvalidURI := NewMockSecurityHandler(HttpMethods.GET, authURI)
			hInvalidURI.URL().RawQuery = "client_id=multi-uri-client&response_type=code&redirect_uri=https://evil.com/cb"
			Expect(router.Execute(hInvalidURI)).To(HaveOccurred())

			// Authenticate user
			authUser := DefaultOAuth2User{}.New(
				[]GrantedAuthority{Authority("ROLE_USER")},
				map[string]any{"sub": "john_doe"},
				"sub",
			)
			contextHolder.GetContext().SetAuthentication(
				OAuth2AuthenticationToken{}.New(authUser, authUser.GetAuthorities(), "internal"),
			)

			// 4. PKCE code_challenge_method not S256
			hPlainPkce := NewMockSecurityHandler(HttpMethods.GET, authURI)
			hPlainPkce.URL().RawQuery = "client_id=my-spa-app&response_type=code&redirect_uri=" + url.QueryEscape(registeredClient.RedirectURIs[0]) + "&code_challenge=abc&code_challenge_method=plain"
			Expect(router.Execute(hPlainPkce)).To(HaveOccurred())

			// 5. Scope validation: unauthorized scope
			hBadScope := NewMockSecurityHandler(HttpMethods.GET, authURI)
			hBadScope.URL().RawQuery = "client_id=my-spa-app&response_type=code&redirect_uri=" + url.QueryEscape(registeredClient.RedirectURIs[0]) + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=openid+unauthorized_scope"
			Expect(router.Execute(hBadScope)).To(HaveOccurred())

			// 6. Scope validation: spaces and valid scopes
			hGoodScope := NewMockSecurityHandler(HttpMethods.GET, authURI)
			hGoodScope.URL().RawQuery = "client_id=my-spa-app&response_type=code&redirect_uri=" + url.QueryEscape(registeredClient.RedirectURIs[0]) + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=+orders+++openid+"
			errGood := router.Execute(hGoodScope)
			Expect(errGood).To(HaveOccurred())
			redirectEx := &DefaultSecurityFilterChainException{}
			Expect(errors.As(errGood, &redirectEx)).To(BeTrue())
			Expect(redirectEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))

			// 7. Missing redirect_uri when client has exactly 1 registered URI (defaults and succeeds)
			singleURIClient := &RegisteredClient{
				ID:                      "single-uri-id",
				ClientID:                "single-uri-client",
				ClientSecret:            "secret",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeAuthorizationCode},
				RedirectURIs:            []string{"https://single.example.com/cb"},
				Scopes:                  []string{"read"},
				RequireProofKey:         false,
			}
			Expect(clientRepo.Save(singleURIClient)).NotTo(HaveOccurred())
			hSingleDefault := NewMockSecurityHandler(HttpMethods.GET, authURI)
			hSingleDefault.URL().RawQuery = "client_id=single-uri-client&response_type=code&scope=read"
			errSingle := router.Execute(hSingleDefault)
			Expect(errSingle).To(HaveOccurred())
			Expect(errors.As(errSingle, &redirectEx)).To(BeTrue())
			Expect(redirectEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))

			// 8. Malformed redirect_uri returns 400
			malformedURIClient := &RegisteredClient{
				ID:                      "malformed-uri-id",
				ClientID:                "malformed-uri-client",
				ClientSecret:            "secret",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeAuthorizationCode},
				RedirectURIs:            []string{"https://single.example.com/cb\x7f"},
				Scopes:                  []string{"read"},
				RequireProofKey:         false,
			}
			Expect(clientRepo.Save(malformedURIClient)).NotTo(HaveOccurred())
			hMalformed := NewMockSecurityHandler(HttpMethods.GET, authURI)
			hMalformed.URL().RawQuery = "client_id=malformed-uri-client&response_type=code&scope=read"
			Expect(router.Execute(hMalformed)).To(HaveOccurred())

			// 9. Failed save of authorization returns 500
			failingSaveAuthSvc := &testMockFailingAuthorizationService{
				OAuth2AuthorizationService: authService,
				failSave:                   true,
			}
			failingSaveFilter := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, failingSaveAuthSvc, generator, km, contextHolder)
			failingSaveRouter := NewMockSecurityRouter()
			failingSaveFilter.RegisterSecurityEndpoint(failingSaveRouter)
			hAuthSaveFail := NewMockSecurityHandler(HttpMethods.GET, authURI)
			hAuthSaveFail.URL().RawQuery = "client_id=single-uri-client&response_type=code&scope=read"
			Expect(failingSaveRouter.Execute(hAuthSaveFail)).To(HaveOccurred())
		})

		It("tests authenticateClient malformed basic auth and missing credentials", func() {
			tokenURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(err).NotTo(HaveOccurred())

			// 1. Basic auth with invalid base64
			hBadB64 := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hBadB64.SetHeader("Authorization", "Basic !!!not-valid-base64!!!")
			hBadB64.SetFormValue("grant_type", "client_credentials")
			Expect(router.Execute(hBadB64)).To(HaveOccurred())

			// 2. Basic auth with no colon
			hNoColon := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hNoColon.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("justusername")))
			hNoColon.SetFormValue("grant_type", "client_credentials")
			Expect(router.Execute(hNoColon)).To(HaveOccurred())

			// 3. Missing client_id entirely
			hNoClient := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hNoClient.SetFormValue("grant_type", "client_credentials")
			Expect(router.Execute(hNoClient)).To(HaveOccurred())

			// 4. Confidential client with empty secret
			hEmptySecret := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hEmptySecret.SetFormValue("client_id", "my-spa-app")
			hEmptySecret.SetFormValue("client_secret", "")
			hEmptySecret.SetFormValue("grant_type", "client_credentials")
			Expect(router.Execute(hEmptySecret)).To(HaveOccurred())
		})

		It("tests handleToken grant restrictions, client_credentials errors, and refresh_token errors", func() {
			tokenURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/token")
			Expect(err).NotTo(HaveOccurred())

			// 1. Public client requesting unauthorized grant (client_credentials)
			publicClient := &RegisteredClient{
				ID:                          "public-client-id",
				ClientID:                    "public-client",
				ClientAuthenticationMethods: []ClientAuthenticationMethod{ClientAuthMethodNone},
				AuthorizationGrantTypes:     []AuthorizationGrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken},
				RedirectURIs:                []string{"https://public.example.com/cb"},
				Scopes:                      []string{"read"},
			}
			Expect(clientRepo.Save(publicClient)).NotTo(HaveOccurred())

			hPubCC := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hPubCC.SetFormValue("client_id", "public-client")
			hPubCC.SetFormValue("grant_type", "client_credentials")
			Expect(router.Execute(hPubCC)).To(HaveOccurred())

			// 2. Unsupported grant type
			hUnsupp := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hUnsupp.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hUnsupp.SetFormValue("grant_type", "password")
			Expect(router.Execute(hUnsupp)).To(HaveOccurred())

			// 3. handleAuthorizationCodeGrant client ID mismatch
			diffClientAuth := &OAuth2Authorization{
				ID:                 "diff-client-auth",
				RegisteredClientID: "some-other-client-id",
				PrincipalName:      "user-diff",
				AuthorizationCode: &AuthorizationCode{
					Value:               "diff-client-code",
					IssuedAt:            time.Now(),
					ExpiresAt:           time.Now().Add(5 * time.Minute),
					RedirectURI:         registeredClient.RedirectURIs[0],
					RedirectURISupplied: true,
				},
			}
			Expect(authService.Save(diffClientAuth)).NotTo(HaveOccurred())
			hDiffClient := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hDiffClient.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hDiffClient.SetFormValue("grant_type", "authorization_code")
			hDiffClient.SetFormValue("code", "diff-client-code")
			hDiffClient.SetFormValue("redirect_uri", registeredClient.RedirectURIs[0])
			Expect(router.Execute(hDiffClient)).To(HaveOccurred())

			// 4. handleAuthorizationCodeGrant with failing token generator
			failingGenFilter := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, authService, &testMockFailingTokenGenerator{}, km, contextHolder)
			failingGenRouter := NewMockSecurityRouter()
			failingGenFilter.RegisterSecurityEndpoint(failingGenRouter)

			codeForFailGen := &OAuth2Authorization{
				ID:                 "fail-gen-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-fail-gen",
				AuthorizationCode: &AuthorizationCode{
					Value:               "fail-gen-code",
					IssuedAt:            time.Now(),
					ExpiresAt:           time.Now().Add(5 * time.Minute),
					RedirectURI:         registeredClient.RedirectURIs[0],
					RedirectURISupplied: true,
				},
			}
			Expect(authService.Save(codeForFailGen)).NotTo(HaveOccurred())
			hFailGen := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hFailGen.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hFailGen.SetFormValue("grant_type", "authorization_code")
			hFailGen.SetFormValue("code", "fail-gen-code")
			hFailGen.SetFormValue("redirect_uri", registeredClient.RedirectURIs[0])
			Expect(failingGenRouter.Execute(hFailGen)).To(HaveOccurred())

			// 5. handleClientCredentialsGrant client not authorized
			noCCClient := &RegisteredClient{
				ID:                      "no-cc-id",
				ClientID:                "no-cc-client",
				ClientSecret:            "secret",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeAuthorizationCode},
				RedirectURIs:            []string{"https://app.example.com/cb"},
			}
			Expect(clientRepo.Save(noCCClient)).NotTo(HaveOccurred())
			hNoCC := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hNoCC.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("no-cc-client:secret")))
			hNoCC.SetFormValue("grant_type", "client_credentials")
			Expect(router.Execute(hNoCC)).To(HaveOccurred())

			// 6. handleClientCredentialsGrant failing token generator
			hCCFailGen := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hCCFailGen.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hCCFailGen.SetFormValue("grant_type", "client_credentials")
			Expect(failingGenRouter.Execute(hCCFailGen)).To(HaveOccurred())

			// 7. handleRefreshTokenGrant client not registered for refresh_token
			noRTClient := &RegisteredClient{
				ID:                      "no-rt-id",
				ClientID:                "no-rt-client",
				ClientSecret:            "secret",
				AuthorizationGrantTypes: []AuthorizationGrantType{GrantTypeClientCredentials},
			}
			Expect(clientRepo.Save(noRTClient)).NotTo(HaveOccurred())
			hNoRT := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hNoRT.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("no-rt-client:secret")))
			hNoRT.SetFormValue("grant_type", "refresh_token")
			hNoRT.SetFormValue("refresh_token", "some-rt")
			Expect(router.Execute(hNoRT)).To(HaveOccurred())

			// 8. handleRefreshTokenGrant invalid / unknown refresh token
			hBadRT := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hBadRT.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hBadRT.SetFormValue("grant_type", "refresh_token")
			hBadRT.SetFormValue("refresh_token", "non-existent-rt")
			Expect(router.Execute(hBadRT)).To(HaveOccurred())

			// 9. handleRefreshTokenGrant client ID mismatch
			diffClientRTAuth := &OAuth2Authorization{
				ID:                 "diff-client-rt-auth",
				RegisteredClientID: "other-client-uuid",
				PrincipalName:      "user-rt",
				RefreshToken:       NewOAuth2RefreshToken("diff-client-rt", time.Now(), time.Now().Add(time.Hour)),
			}
			Expect(authService.Save(diffClientRTAuth)).NotTo(HaveOccurred())
			hDiffClientRT := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hDiffClientRT.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hDiffClientRT.SetFormValue("grant_type", "refresh_token")
			hDiffClientRT.SetFormValue("refresh_token", "diff-client-rt")
			Expect(router.Execute(hDiffClientRT)).To(HaveOccurred())

			// 10. handleRefreshTokenGrant failing token generator
			rtForFailGen := &OAuth2Authorization{
				ID:                 "rt-fail-gen-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-rt",
				RefreshToken:       NewOAuth2RefreshToken("rt-fail-gen-val", time.Now(), time.Now().Add(time.Hour)),
			}
			Expect(authService.Save(rtForFailGen)).NotTo(HaveOccurred())
			hRTFailGen := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hRTFailGen.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRTFailGen.SetFormValue("grant_type", "refresh_token")
			hRTFailGen.SetFormValue("refresh_token", "rt-fail-gen-val")
			Expect(failingGenRouter.Execute(hRTFailGen)).To(HaveOccurred())

			// 11. handleRefreshTokenGrant failing SaveTokens
			failingSaveTokensAuthSvc := &testMockFailingSaveTokensAuthService{
				OAuth2AuthorizationService: authService,
			}
			failingSaveTokensFilter := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, failingSaveTokensAuthSvc, generator, km, contextHolder)
			failingSaveTokensRouter := NewMockSecurityRouter()
			failingSaveTokensFilter.RegisterSecurityEndpoint(failingSaveTokensRouter)

			rtForFailSave := &OAuth2Authorization{
				ID:                 "rt-fail-save-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-rt",
				RefreshToken:       NewOAuth2RefreshToken("rt-fail-save-val", time.Now(), time.Now().Add(time.Hour)),
			}
			Expect(authService.Save(rtForFailSave)).NotTo(HaveOccurred())
			hRTFailSave := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hRTFailSave.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRTFailSave.SetFormValue("grant_type", "refresh_token")
			hRTFailSave.SetFormValue("refresh_token", "rt-fail-save-val")
			Expect(failingSaveTokensRouter.Execute(hRTFailSave)).To(HaveOccurred())

			// 12. handleRefreshTokenGrant with generator returning nil refresh token (outRefreshToken defaults to auth.RefreshToken)
			now := time.Now()
			atForNilRT := NewOAuth2AccessToken(TokenTypeBearer, "nil-rt-at", now, now.Add(time.Hour), []string{"read"})
			nilRTGen := &testMockNilRefreshTokenGenerator{accessToken: atForNilRT}
			nilRTFilter := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, authService, nilRTGen, km, contextHolder)
			nilRTRouter := NewMockSecurityRouter()
			nilRTFilter.RegisterSecurityEndpoint(nilRTRouter)

			rtForNilRT := &OAuth2Authorization{
				ID:                 "rt-nil-rt-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-rt",
				RefreshToken:       NewOAuth2RefreshToken("nil-rt-val", time.Now(), time.Now().Add(time.Hour)),
			}
			Expect(authService.Save(rtForNilRT)).NotTo(HaveOccurred())
			hNilRT := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
			hNilRT.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hNilRT.SetFormValue("grant_type", "refresh_token")
			hNilRT.SetFormValue("refresh_token", "nil-rt-val")
			Expect(nilRTRouter.Execute(hNilRT)).To(Succeed())
		})

		It("tests handleJWKS error, handleIntrospect with unknown client ID, and handleRevoke for refresh token and different client", func() {
			// 1. handleJWKS error
			failingJWKSFilter := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, authService, generator, &testMockFailingJWKSource{}, contextHolder)
			failingJWKSRouter := NewMockSecurityRouter()
			failingJWKSFilter.RegisterSecurityEndpoint(failingJWKSRouter)

			jwksURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/jwks")
			Expect(err).NotTo(HaveOccurred())
			hJWKSFail := NewMockSecurityHandler(HttpMethods.GET, jwksURI)
			Expect(failingJWKSRouter.Execute(hJWKSFail)).To(HaveOccurred())

			// 2. handleIntrospect when clientRepo fails on RegisteredClientID
			now := time.Now()
			atUnknownClient := NewOAuth2AccessToken(TokenTypeBearer, "intro-unknown-client-at", now, now.Add(time.Hour), []string{"read"})
			authUnknownClient := &OAuth2Authorization{
				ID:                 "intro-unknown-client-auth",
				RegisteredClientID: "non-existent-client-id",
				PrincipalName:      "user-unknown",
				AccessToken:        atUnknownClient,
			}
			Expect(authService.Save(authUnknownClient)).NotTo(HaveOccurred())

			introspectURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/introspect")
			Expect(err).NotTo(HaveOccurred())
			hIntroUnknown := NewMockSecurityHandler(HttpMethods.POST, introspectURI)
			hIntroUnknown.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hIntroUnknown.SetFormValue("token", "intro-unknown-client-at")
			Expect(router.Execute(hIntroUnknown)).To(Succeed())
			var introResp map[string]any
			Expect(json.Unmarshal(hIntroUnknown.Res.Body.Bytes(), &introResp)).To(Succeed())
			Expect(introResp["active"]).To(BeTrue())
			Expect(introResp["client_id"]).To(Equal("non-existent-client-id"))

			// 3. handleRevoke for refresh token
			rtRevoke := NewOAuth2RefreshToken("revoke-rt-val", now, now.Add(24*time.Hour))
			authRevokeRT := &OAuth2Authorization{
				ID:                 "revoke-rt-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-revoke-rt",
				RefreshToken:       rtRevoke,
			}
			Expect(authService.Save(authRevokeRT)).NotTo(HaveOccurred())

			revokeURI, err := url.Parse("https://auth.beamfoundry.com/oauth2/revoke")
			Expect(err).NotTo(HaveOccurred())
			hRevokeRT := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevokeRT.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRevokeRT.SetFormValue("token", "revoke-rt-val")
			Expect(router.Execute(hRevokeRT)).To(Succeed())
			Expect(hRevokeRT.Res.Body.String()).To(Equal("{}"))

			// 4. handleRevoke for token belonging to a different client (no-op, succeeds)
			rtOtherClient := NewOAuth2RefreshToken("other-client-rt-val", now, now.Add(24*time.Hour))
			authOtherClient := &OAuth2Authorization{
				ID:                 "other-client-auth",
				RegisteredClientID: "other-client-id",
				PrincipalName:      "user-other",
				RefreshToken:       rtOtherClient,
			}
			Expect(authService.Save(authOtherClient)).NotTo(HaveOccurred())
			hRevokeOther := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevokeOther.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRevokeOther.SetFormValue("token", "other-client-rt-val")
			Expect(router.Execute(hRevokeOther)).To(Succeed())

			// 5. handleRevoke when FindByToken fails for refresh_token
			failingRTFindAuthSvc := &testMockFailingAuthorizationService{
				OAuth2AuthorizationService: authService,
				failFindByRefreshTokenOnly: true,
			}
			failingRTFindFilter := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, failingRTFindAuthSvc, generator, km, contextHolder)
			failingRTFindRouter := NewMockSecurityRouter()
			failingRTFindFilter.RegisterSecurityEndpoint(failingRTFindRouter)

			hRevokeRTFindFail := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevokeRTFindFail.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRevokeRTFindFail.SetFormValue("token", "non-existent-access-token")
			Expect(failingRTFindRouter.Execute(hRevokeRTFindFail)).To(HaveOccurred())

			// 6. handleRevoke when Remove fails for refresh_token
			rtRemoveFailAuth := &OAuth2Authorization{
				ID:                 "rt-rm-fail-auth",
				RegisteredClientID: registeredClient.ID,
				PrincipalName:      "user-rt",
				RefreshToken:       NewOAuth2RefreshToken("rt-rm-fail-val", time.Now(), time.Now().Add(time.Hour)),
			}
			Expect(authService.Save(rtRemoveFailAuth)).NotTo(HaveOccurred())

			failingRTRemoveAuthSvc := &testMockFailingAuthorizationService{
				OAuth2AuthorizationService: authService,
				failRemove:                 true,
			}
			failingRTRemoveFilter := OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, failingRTRemoveAuthSvc, generator, km, contextHolder)
			failingRTRemoveRouter := NewMockSecurityRouter()
			failingRTRemoveFilter.RegisterSecurityEndpoint(failingRTRemoveRouter)

			hRevokeRTRmFail := NewMockSecurityHandler(HttpMethods.POST, revokeURI)
			hRevokeRTRmFail.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-spa-app:client-secret-123")))
			hRevokeRTRmFail.SetFormValue("token", "rt-rm-fail-val")
			Expect(failingRTRemoveRouter.Execute(hRevokeRTRmFail)).To(HaveOccurred())
		})
	})
})

// testMockFailingJWKSource is a JWKSource test double that always returns errors.
type testMockFailingJWKSource struct{}

// GetJWKSet returns a simulated JWKSet retrieval error.
func (this *testMockFailingJWKSource) GetJWKSet() (*JWKSet, Error) {
	return nil, NewError("JWKSetError", "failed to get jwk set")
}

// GetSigningKey returns a simulated missing signing key error.
//
//nolint:revive // JWKSource interface requires 4 return values
func (this *testMockFailingJWKSource) GetSigningKey() (kid string, privKey any, alg string, err Error) {
	return "", nil, "", NewError("NoSigningKey", "no key")
}

// GetVerificationKey returns a simulated missing verification key error.
func (this *testMockFailingJWKSource) GetVerificationKey(_ string) (pubKey any, alg string, err Error) {
	return nil, "", NewError("NoVerificationKey", "no key")
}

// testMockFailingAuthorizationService wraps an OAuth2AuthorizationService to simulate storage failures on specific operations.
type testMockFailingAuthorizationService struct {
	OAuth2AuthorizationService
	failSave                   bool
	failFindByToken            bool
	failFindByRefreshTokenOnly bool
	failRemove                 bool
}

// Save returns a simulated storage error if failSave is true, or delegates to the embedded service.
func (this *testMockFailingAuthorizationService) Save(auth *OAuth2Authorization) Error {
	if this.failSave {
		return NewError("StorageError", "database write failure")
	}
	return this.OAuth2AuthorizationService.Save(auth)
}

// FindByToken returns a simulated storage error if failFindByToken is true, or delegates to the embedded service.
func (this *testMockFailingAuthorizationService) FindByToken(token, tokenType string) (*OAuth2Authorization, Error) {
	if this.failFindByToken {
		return nil, NewError("StorageError", "database lookup failure")
	}
	if this.failFindByRefreshTokenOnly && tokenType == "refresh_token" {
		return nil, NewError("StorageError", "database lookup failure")
	}
	return this.OAuth2AuthorizationService.FindByToken(token, tokenType)
}

// Remove returns a simulated storage error if failRemove is true, or delegates to the embedded service.
func (this *testMockFailingAuthorizationService) Remove(auth *OAuth2Authorization) Error {
	if this.failRemove {
		return NewError("StorageError", "database delete failure")
	}
	return this.OAuth2AuthorizationService.Remove(auth)
}

// testMockFailingSaveTokensAuthService simulates failures in SaveTokens.
type testMockFailingSaveTokensAuthService struct {
	OAuth2AuthorizationService
}

func (this *testMockFailingSaveTokensAuthService) SaveTokens(_, _ string, _ *OAuth2AccessToken, _ *OAuth2RefreshToken) Error {
	return NewError("StorageError", "database write failure")
}

// testMockFailingTokenGenerator always returns an error when generating tokens.
type testMockFailingTokenGenerator struct{}

func (this *testMockFailingTokenGenerator) Generate(_ *OAuth2Authorization, _ *RegisteredClient) (*OAuth2AccessToken, *OAuth2RefreshToken, Error) {
	return nil, nil, NewError("TokenGenError", "token generation failed")
}

// testMockFailingJwtEncoder always returns an error.
type testMockFailingJwtEncoder struct{}

func (this *testMockFailingJwtEncoder) Encode(_ *JwtEncoderParameters) (*Jwt, Error) {
	return nil, NewError("JwtEncodeError", "failed to encode jwt")
}

// testMockNilRefreshTokenGenerator returns a nil refresh token to test non-rotated refresh token branches.
type testMockNilRefreshTokenGenerator struct {
	accessToken *OAuth2AccessToken
}

func (this *testMockNilRefreshTokenGenerator) Generate(_ *OAuth2Authorization, _ *RegisteredClient) (*OAuth2AccessToken, *OAuth2RefreshToken, Error) {
	return this.accessToken, nil, nil
}

// testMockFailingWriteSecurityHandler fails on Write calls.
type testMockFailingWriteSecurityHandler struct {
	SecurityHandler
}

func (this *testMockFailingWriteSecurityHandler) Write(_ []byte) (int, error) {
	return 0, errors.New("simulated write error")
}
