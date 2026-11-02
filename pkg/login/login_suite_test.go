package login_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/login"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/web"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLogin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OAuth2 Login Suite")
}

type mockAuthManager struct {
	Manager
	authenticateFunc func(Authentication) (Authentication, AuthenticationException)
}

func (this *mockAuthManager) Authenticate(auth Authentication) (Authentication, AuthenticationException) {
	if this.authenticateFunc != nil {
		return this.authenticateFunc(auth)
	}
	return auth, nil
}

type mockTestJwtDecoder struct {
	jwt *Jwt
	err Error
}

func (this *mockTestJwtDecoder) Decode(_ string) (*Jwt, Error) {
	if this.err != nil {
		return nil, this.err
	}
	return this.jwt, nil
}

type mockSecurityContext struct {
	auth  Authentication
	debug string
}

func (this *mockSecurityContext) GetAuthentication() Authentication    { return this.auth }
func (this *mockSecurityContext) SetAuthentication(a Authentication)   { this.auth = a }
func (this *mockSecurityContext) SetHTTPPolicyDebugValue(debug string) { this.debug = debug }
func (this *mockSecurityContext) GetHTTPPolicyDebugValue() string      { return this.debug }

type mockSecurityContextHolder struct {
	ctx SecurityContext
}

func (this *mockSecurityContextHolder) ClearContext() { this.ctx = nil }
func (this *mockSecurityContextHolder) SetContext(sc SecurityContext) {
	this.ctx = sc
}

func (this *mockSecurityContextHolder) GetContext() SecurityContext {
	if this.ctx == nil {
		this.ctx = &mockSecurityContext{}
	}
	return this.ctx
}

var _ = Describe("OAuth2 Authorization Request & PKCE", func() {
	It("generates an authorization request with PKCE S256 parameters", func() {
		reg := ClientRegistrationBuilder{}.New("google").
			ClientID("google-client-id").
			RedirectURI("https://my-app.com/login/oauth2/code/google").
			AuthorizationURI("https://accounts.google.com/o/oauth2/v2/auth").
			Scope("openid", "profile", "email").
			Build()

		req, err := GenerateAuthorizationRequest(reg)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.ClientID).To(Equal("google-client-id"))
		Expect(req.RedirectURI).To(Equal("https://my-app.com/login/oauth2/code/google"))
		Expect(req.State).NotTo(BeEmpty())
		Expect(req.CodeVerifier).NotTo(BeEmpty())
		Expect(req.CodeChallenge).NotTo(BeEmpty())
		Expect(req.CodeChallengeMethod).To(Equal("S256"))

		authURI := BuildAuthorizationURI(req)
		Expect(authURI).To(ContainSubstring("https://accounts.google.com/o/oauth2/v2/auth?"))
		Expect(authURI).To(ContainSubstring("client_id=google-client-id"))
		Expect(authURI).To(ContainSubstring("response_type=code"))
		Expect(authURI).To(ContainSubstring("code_challenge=" + req.CodeChallenge))
		Expect(authURI).To(ContainSubstring("code_challenge_method=S256"))
		Expect(authURI).To(ContainSubstring("state=" + req.State))
	})
})

var _ = Describe("SessionAuthorizationRequestRepository", func() {
	It("stores, retrieves, and removes the authorization request from session", func() {
		u, err := url.Parse("https://my-app.com/oauth2/authorization/google")
		Expect(err).NotTo(HaveOccurred())
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		repo := SessionAuthorizationRequestRepository{}.New()

		authReq := &OAuth2AuthorizationRequest{
			ClientID: "client-1",
			State:    "state-12345",
		}

		repo.SaveAuthorizationRequest(authReq, handler)

		loaded := repo.LoadAuthorizationRequest(handler)
		Expect(loaded).NotTo(BeNil())
		Expect(loaded.ClientID).To(Equal("client-1"))
		Expect(loaded.State).To(Equal("state-12345"))

		removed := repo.RemoveAuthorizationRequest(handler)
		Expect(removed).NotTo(BeNil())
		Expect(removed.State).To(Equal("state-12345"))

		Expect(repo.LoadAuthorizationRequest(handler)).To(BeNil())
	})
})

var _ = Describe("OAuth2LoginAuthenticationProvider", func() {
	var mockIdPServer *httptest.Server

	AfterEach(func() {
		if mockIdPServer != nil {
			mockIdPServer.Close()
		}
	})

	It("exchanges authorization code for tokens and loads user identity", func() {
		mockIdPServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/oauth/token":
				Expect(r.ParseForm()).To(Succeed())
				Expect(r.Form.Get("grant_type")).To(Equal("authorization_code"))
				Expect(r.Form.Get("code")).To(Equal("auth-code-xyz"))
				Expect(r.Form.Get("code_verifier")).To(Equal("verifier-abc"))

				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "user-access-token-999",
					"token_type":   "Bearer",
					"expires_in":   3600,
					"scope":        "read user",
				})).To(Succeed())
			case "/userinfo":
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer user-access-token-999"))
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"sub":   "github-user-42",
					"name":  "Octocat",
					"email": "octocat@github.com",
				})).To(Succeed())
			default:
				http.NotFound(w, r)
			}
		}))

		reg := ClientRegistrationBuilder{}.New("github").
			ClientID("gh-client-id").
			ClientSecret("gh-secret").
			TokenURI(mockIdPServer.URL + "/oauth/token").
			UserInfoURI(mockIdPServer.URL + "/userinfo").
			UserNameAttributeName("name").
			Build()

		exchange := OAuth2AuthorizationExchange{
			AuthorizationRequest: &OAuth2AuthorizationRequest{
				ClientID:     "gh-client-id",
				CodeVerifier: "verifier-abc",
			},
			AuthorizationResponse: &OAuth2AuthorizationResponse{
				Code: "auth-code-xyz",
			},
		}

		loginToken := OAuth2LoginAuthenticationToken{}.New(reg, exchange)

		userService := DefaultOAuth2UserService{}.New(mockIdPServer.Client())
		provider := OAuth2LoginAuthenticationProvider{}.New(mockIdPServer.Client(), userService, nil)

		Expect(provider.Supports(loginToken)).To(BeTrue())

		authResult, authEx := provider.Authenticate(loginToken)
		Expect(authEx).NotTo(HaveOccurred())
		Expect(authResult.IsAuthenticated()).To(BeTrue())
		Expect(authResult.GetName()).To(Equal("Octocat"))

		oauthAuthToken, ok := authResult.(*OAuth2AuthenticationToken)
		Expect(ok).To(BeTrue())
		Expect(oauthAuthToken.AuthorizedClientRegistrationID).To(Equal("github"))

		user, ok := oauthAuthToken.Principal.(OAuth2User)
		Expect(ok).To(BeTrue())
		Expect(user.GetAttributes()).To(HaveKeyWithValue("email", "octocat@github.com"))
	})
})

var _ = Describe("OAuth2LoginAuthenticationFilter", func() {
	var (
		regRepo       ClientRegistrationRepository
		authManager   *mockAuthManager
		contextHolder *mockSecurityContextHolder
		filter        *OAuth2LoginAuthenticationFilter
		reg           *ClientRegistration
	)

	BeforeEach(func() {
		reg = ClientRegistrationBuilder{}.New("google").
			ClientID("google-client-id").
			ClientSecret("google-secret").
			AuthorizationURI("https://accounts.google.com/o/oauth2/v2/auth").
			TokenURI("https://oauth2.googleapis.com/token").
			Build()

		regRepo = InMemoryClientRegistrationRepository{}.New(reg)
		authManager = &mockAuthManager{}
		contextHolder = &mockSecurityContextHolder{}
		filter = OAuth2LoginAuthenticationFilter{}.New(regRepo, authManager, contextHolder)
	})

	Context("Authorization initiation endpoint", func() {
		It("registers endpoint and redirects to authorization URI with PKCE", func() {
			router := NewMockSecurityRouter()
			filter.RegisterSecurityEndpoint(router)

			u, err := url.Parse("https://my-app.com/oauth2/authorization/google")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			err = router.Execute(handler)
			Expect(err).To(HaveOccurred())
			redirectEx := &DefaultSecurityFilterChainException{}
			ok := errors.As(err, &redirectEx)
			Expect(ok).To(BeTrue())
			Expect(redirectEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
			Expect(redirectEx.Status()).To(Equal(302))
			Expect(redirectEx.To()).To(ContainSubstring("https://accounts.google.com/o/oauth2/v2/auth"))
			Expect(redirectEx.To()).To(ContainSubstring("client_id=google-client-id"))
			Expect(redirectEx.To()).To(ContainSubstring("code_challenge="))

			// Verify authorization request was saved to session
			repo := SessionAuthorizationRequestRepository{}.New()
			savedReq := repo.LoadAuthorizationRequest(handler)
			Expect(savedReq).NotTo(BeNil())
			Expect(savedReq.ClientID).To(Equal("google-client-id"))
		})
	})

	Context("Callback endpoint", func() {
		It("reports error on CSRF state mismatch", func() {
			u, err := url.Parse("https://my-app.com/login/oauth2/code/google?code=valid-code&state=attacker-state")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			// Session has legitimate state
			repo := SessionAuthorizationRequestRepository{}.New()
			repo.SaveAuthorizationRequest(&OAuth2AuthorizationRequest{
				State: "legitimate-state",
			}, handler)

			chainEx := filter.Authenticate(handler)
			Expect(chainEx).To(HaveOccurred())
			defaultEx, ok := chainEx.(*DefaultSecurityFilterChainException)
			Expect(ok).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(400))
		})

		It("ignores requests not matching login processing URL", func() {
			u, err := url.Parse("https://my-app.com/other/path")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			chainEx := filter.Authenticate(handler)
			Expect(chainEx).To(HaveOccurred())
			Expect(chainEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))
		})

		It("returns 400 when registration ID is unknown", func() {
			u, err := url.Parse("https://my-app.com/login/oauth2/code/unknown-idp?code=c&state=s")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			chainEx := filter.Authenticate(handler)
			Expect(chainEx).To(HaveOccurred())
			defaultEx, ok := chainEx.(*DefaultSecurityFilterChainException)
			Expect(ok).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(400))
		})

		It("returns 401 when IdP returns an error query parameter", func() {
			u, err := url.Parse("https://my-app.com/login/oauth2/code/google?error=access_denied&error_description=user_cancelled")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			chainEx := filter.Authenticate(handler)
			Expect(chainEx).To(HaveOccurred())
			defaultEx, ok := chainEx.(*DefaultSecurityFilterChainException)
			Expect(ok).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(401))
		})

		It("returns 400 when no authorization request exists in session", func() {
			u, err := url.Parse("https://my-app.com/login/oauth2/code/google?code=valid-code&state=good-state")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			chainEx := filter.Authenticate(handler)
			Expect(chainEx).To(HaveOccurred())
			defaultEx, ok := chainEx.(*DefaultSecurityFilterChainException)
			Expect(ok).To(BeTrue())
			Expect(defaultEx.Status()).To(Equal(400))
		})

		It("authenticates user and redirects to success URL on valid callback", func() {
			u, err := url.Parse("https://my-app.com/login/oauth2/code/google?code=valid-code&state=good-state")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			repo := SessionAuthorizationRequestRepository{}.New()
			repo.SaveAuthorizationRequest(&OAuth2AuthorizationRequest{
				State:       "good-state",
				RedirectURI: "/login/oauth2/code/google",
			}, handler)

			authManager.authenticateFunc = func(_ Authentication) (Authentication, AuthenticationException) {
				user := DefaultOAuth2User{}.New(
					[]GrantedAuthority{Authority("ROLE_USER")},
					map[string]any{"sub": "google-user-123"},
					"sub",
				)
				return OAuth2AuthenticationToken{}.New(user, user.GetAuthorities(), "google"), nil
			}

			chainEx := filter.Authenticate(handler)
			Expect(chainEx).To(HaveOccurred())
			Expect(chainEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))

			defaultEx, ok := chainEx.(*DefaultSecurityFilterChainException)
			Expect(ok).To(BeTrue())
			Expect(defaultEx.To()).To(Equal("/"))

			// Verify authentication in SecurityContext
			ctxAuth := contextHolder.GetContext().GetAuthentication()
			Expect(ctxAuth).NotTo(BeNil())
			Expect(ctxAuth.GetName()).To(Equal("google-user-123"))
		})
	})

	Context("AuthenticationRequired", func() {
		It("redirects unauthenticated requests to authorization initiation endpoint", func() {
			filter.WithDefaultRegistrationID("google")
			u, err := url.Parse("https://my-app.com/protected/dashboard")
			Expect(err).NotTo(HaveOccurred())
			handler := NewMockSecurityHandler(HttpMethods.GET, u)

			chainEx := filter.AuthenticationRequired(handler)
			Expect(chainEx).To(HaveOccurred())
			Expect(chainEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))

			defaultEx, ok := chainEx.(*DefaultSecurityFilterChainException)
			Expect(ok).To(BeTrue())
			Expect(defaultEx.To()).To(Equal("/oauth2/authorization/google"))
			Expect(handler.SessionValue("redirect")).To(Equal("/protected/dashboard"))
		})
	})

	Context("Filter WithContext lifecycle and constructors", func() {
		It("tests constructors, WithDefaultSuccessURL, Config and WithContext lifecycle", func() {
			repo := NewSessionAuthorizationRequestRepository()
			Expect(repo).NotTo(BeNil())

			f := NewOAuth2LoginAuthenticationFilter(regRepo, authManager, contextHolder).
				WithDefaultSuccessURL("/dashboard")
			Expect(f.Config()).NotTo(BeNil())
			Expect(f.Config().DefaultSuccessURL).To(Equal("/dashboard"))

			// Non-HttpSecurity context parent
			invalidCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, "wrong-type")
			err := f.WithContext(invalidCtx)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("IllegalArgumentException"))

			// HttpSecurity missing filter config
			builderEmpty := &HttpSecurityBuilder{}
			secEmpty := builderEmpty.Build()
			missingCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, secEmpty)
			err = f.WithContext(missingCtx)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("IllegalArgumentException"))

			// HttpSecurity with invalid config type
			builderInvalid := &HttpSecurityBuilder{}
			builderInvalid.AddCustomSecurityFilter("oAuth2LoginAuthenticationFilter", 12345)
			secInvalid := builderInvalid.Build()
			invalidCfgCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, secInvalid)
			err = f.WithContext(invalidCfgCtx)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("IllegalArgumentException"))

			// HttpSecurity with valid OAuth2LoginConfig
			builderValid := &HttpSecurityBuilder{}
			cfg := &OAuth2LoginConfig{
				DefaultRegistrationID: "custom-id",
				DefaultSuccessURL:     "/welcome",
			}
			builderValid.AddCustomSecurityFilter("oAuth2LoginAuthenticationFilter", cfg)
			secValid := builderValid.Build()
			validCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, secValid)
			err = f.WithContext(validCtx)
			Expect(err).NotTo(HaveOccurred())
			Expect(f.Config().DefaultRegistrationID).To(Equal("custom-id"))
			Expect(f.Config().DefaultSuccessURL).To(Equal("/welcome"))

			// Background context
			fNoParent := &OAuth2LoginAuthenticationFilter{}
			err = fNoParent.WithContext(context.Background())
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("DefaultOidcUserService and OIDC Login Flow", func() {
		It("tests DefaultOidcUserService and DefaultOAuth2UserService", func() {
			userServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer oidc-access-tok"))
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"sub":   "alice-sub-id",
					"name":  "Alice In Wonderland",
					"email": "alice@example.com",
				})).To(Succeed())
			}))
			defer userServer.Close()

			oauthSvc := NewDefaultOAuth2UserService(userServer.Client())
			oidcSvc := NewDefaultOidcUserService(oauthSvc)

			reg := ClientRegistrationBuilder{}.New("oidc-idp").
				ClientID("client-oidc").
				UserInfoURI(userServer.URL).
				UserNameAttributeName("name").
				Build()

			now := time.Now()
			token := OAuth2AccessToken{}.New(
				TokenTypeBearer,
				"oidc-access-tok",
				now,
				now.Add(1*time.Hour),
				[]string{"openid", "email"},
			)

			//nolint:gosec // mock token in test
			idToken := &OidcIdToken{
				TokenValue: "raw.id.token",
				Claims: map[string]any{
					"sub": "alice-sub-id",
					"iss": "https://idp.example.com",
				},
			}

			userReq := &OidcUserRequest{
				ClientRegistration: reg,
				AccessToken:        token,
				IdToken:            idToken,
			}

			oidcUser, err := oidcSvc.LoadUser(userReq)
			Expect(err).NotTo(HaveOccurred())
			Expect(oidcUser.GetName()).To(Equal("Alice In Wonderland"))
			Expect(oidcUser.GetAttributes()).To(HaveKeyWithValue("email", "alice@example.com"))

			var authNames []string
			for _, a := range oidcUser.GetAuthorities() {
				authNames = append(authNames, a.Authority())
			}
			Expect(authNames).To(ContainElement("ROLE_USER"))
			Expect(authNames).To(ContainElement("SCOPE_openid"))
			Expect(authNames).To(ContainElement("SCOPE_email"))

			// UserInfo subject mismatch rejected
			userReqMismatch := &OidcUserRequest{
				ClientRegistration: reg,
				AccessToken:        token,
				//nolint:gosec // mock token in test
				IdToken: &OidcIdToken{
					TokenValue: "raw.id.token",
					Claims: map[string]any{
						"sub": "different-sub-id",
					},
				},
			}
			_, err = oidcSvc.LoadUser(userReqMismatch)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("InvalidUserInfoResponse"))

			// Missing UserInfo or IdToken subject rejected
			userReqMissingSub := &OidcUserRequest{
				ClientRegistration: reg,
				AccessToken:        token,
				//nolint:gosec // mock token in test
				IdToken: &OidcIdToken{
					TokenValue: "raw.id.token",
					Claims:     map[string]any{},
				},
			}
			_, err = oidcSvc.LoadUser(userReqMissingSub)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("InvalidUserInfoResponse"))
		})

		It("tests OAuth2LoginAuthenticationProvider PostConstruct, OIDC flow, and error branches", func() {
			p := NewOAuth2LoginAuthenticationProvider(nil, nil, nil)
			Expect(p.PostConstruct()).NotTo(HaveOccurred())

			// Non-login token returns error
			nonLoginAuth := OAuth2AuthenticationToken{}.New(nil, nil, "some-reg")
			_, authEx := p.Authenticate(nonLoginAuth)
			Expect(authEx).To(HaveOccurred())

			// AuthorizationResponse error
			reg := ClientRegistrationBuilder{}.New("test-idp").
				ClientID("client-err").
				Build()
			errExchange := OAuth2AuthorizationExchange{
				AuthorizationRequest: &OAuth2AuthorizationRequest{ClientID: "client-err"},
				AuthorizationResponse: &OAuth2AuthorizationResponse{
					Error:     "access_denied",
					ErrorDesc: "User rejected consent",
				},
			}
			loginTokenErr := OAuth2LoginAuthenticationToken{}.New(reg, errExchange)
			_, authEx = p.Authenticate(loginTokenErr)
			Expect(authEx).To(HaveOccurred())

			// Server token endpoint fails (HTTP 500)
			failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer failServer.Close()

			regFail := ClientRegistrationBuilder{}.New("test-idp").
				ClientID("client-fail").
				ClientSecret("secret").
				TokenURI(failServer.URL).
				Build()
			tokenFailExchange := OAuth2AuthorizationExchange{
				AuthorizationRequest:  &OAuth2AuthorizationRequest{ClientID: "client-fail"},
				AuthorizationResponse: &OAuth2AuthorizationResponse{Code: "valid-code"},
			}
			loginTokenFail := OAuth2LoginAuthenticationToken{}.New(regFail, tokenFailExchange)
			pFail := NewOAuth2LoginAuthenticationProvider(failServer.Client(), nil, nil)
			_, authEx = pFail.Authenticate(loginTokenFail)
			Expect(authEx).To(HaveOccurred())
		})

		It("authenticates full OIDC flow with id_token and UserInfo, and rejects invalid id_token", func() {
			headerB64 := "eyJhbGciOiJub25lIn0"
			claimsB64 := "eyJzdWIiOiJhbGljZS1vaWRjIiwiZW1haWwiOiJhbGljZUBvaWRjLmNvbSIsImlzcyI6Imh0dHBzOi8vb2lkYy5leGFtcGxlLmNvbSJ9"
			rawIdToken := headerB64 + "." + claimsB64 + "."

			oidcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/oauth/token":
					//nolint:gosec // mock token endpoint in test
					Expect(json.NewEncoder(w).Encode(map[string]any{
						"access_token": "oidc-at-456",
						"token_type":   "Bearer",
						"expires_in":   3600,
						"scope":        "openid email profile",
						"id_token":     rawIdToken,
					})).To(Succeed())
				case "/userinfo":
					Expect(json.NewEncoder(w).Encode(map[string]any{
						"sub":  "alice-oidc",
						"name": "Alice Oidc User",
					})).To(Succeed())
				default:
					http.NotFound(w, r)
				}
			}))
			defer oidcServer.Close()

			regOidc := ClientRegistrationBuilder{}.New("oidc-flow").
				ClientID("client-oidc-flow").
				ClientSecret("secret").
				TokenURI(oidcServer.URL+"/oauth/token").
				UserInfoURI(oidcServer.URL+"/userinfo").
				UserNameAttributeName("name").
				Scope("openid", "email").
				Build()

			exchange := OAuth2AuthorizationExchange{
				AuthorizationRequest: &OAuth2AuthorizationRequest{
					ClientID:     "client-oidc-flow",
					CodeVerifier: "code-ver",
				},
				AuthorizationResponse: &OAuth2AuthorizationResponse{
					Code: "code-oidc-123",
				},
			}

			loginToken := OAuth2LoginAuthenticationToken{}.New(regOidc, exchange)

			// 1. Unverified token fails when no decoder or jwks is provided
			providerNoDecoder := NewOAuth2LoginAuthenticationProvider(oidcServer.Client(), nil, nil)
			_, noDecEx := providerNoDecoder.Authenticate(loginToken)
			Expect(noDecEx).To(HaveOccurred())

			// 2. Decoder error returns authentication error
			failDecoder := &mockTestJwtDecoder{err: NewError("JwtValidationError", "bad signature")}
			providerBadDecoder := NewOAuth2LoginAuthenticationProvider(oidcServer.Client(), nil, nil).WithJwtDecoder(failDecoder)
			_, badDecEx := providerBadDecoder.Authenticate(loginToken)
			Expect(badDecEx).To(HaveOccurred())

			// 3. Valid decoder succeeds
			validJwt := NewJwt(
				rawIdToken,
				time.Now(),
				time.Now().Add(time.Hour),
				map[string]any{"alg": "none"},
				map[string]any{"sub": "alice-oidc", "email": "alice@oidc.com", "iss": "https://oidc.example.com"},
			)
			decoder := &mockTestJwtDecoder{jwt: validJwt}
			provider := NewOAuth2LoginAuthenticationProvider(oidcServer.Client(), nil, nil).WithJwtDecoder(decoder)

			authResult, authEx := provider.Authenticate(loginToken)
			Expect(authEx).NotTo(HaveOccurred())
			Expect(authResult.IsAuthenticated()).To(BeTrue())
			Expect(authResult.GetName()).To(Equal("Alice Oidc User"))

			oauthAuth, ok := authResult.(*OAuth2AuthenticationToken)
			Expect(ok).To(BeTrue())
			oidcUser, ok := oauthAuth.Principal.(OidcUser)
			Expect(ok).To(BeTrue())
			Expect(oidcUser.GetIdToken()).NotTo(BeNil())
			Expect(oidcUser.GetIdToken().TokenValue).To(Equal(rawIdToken))
			Expect(oidcUser.GetAttributes()).To(HaveKeyWithValue("email", "alice@oidc.com"))

			// 3b. Missing id_token in token response for OIDC flow returns invalid_grant error
			noIdTokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				//nolint:gosec // mock token endpoint in test
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "oidc-at-no-id",
					"token_type":   "Bearer",
					"expires_in":   3600,
					"scope":        "openid email",
				})).To(Succeed())
			}))
			defer noIdTokenServer.Close()

			regNoIdToken := ClientRegistrationBuilder{}.New("oidc-no-id-token").
				ClientID("client-oidc-no-id").
				ClientSecret("secret").
				TokenURI(noIdTokenServer.URL).
				Scope("openid").
				Build()
			loginTokenNoId := OAuth2LoginAuthenticationToken{}.New(regNoIdToken, exchange)
			providerNoId := NewOAuth2LoginAuthenticationProvider(noIdTokenServer.Client(), nil, nil).WithJwtDecoder(decoder)
			_, missingIdEx := providerNoId.Authenticate(loginTokenNoId)
			Expect(missingIdEx).To(HaveOccurred())
			oauthEx, ok := missingIdEx.(*OAuth2AuthenticationException)
			Expect(ok).To(BeTrue())
			Expect(oauthEx.OAuth2Error().ErrorCode).To(Equal(OAuth2ErrorInvalidGrant))
			Expect(oauthEx.OAuth2Error().ErrorDescription).To(ContainSubstring("missing id_token"))

			// 4. Reusing JWKS-backed decoder per RegistrationID
			regJwks := ClientRegistrationBuilder{}.New("reg-jwks-reuse").
				ClientID("client-jwks-reuse").
				JwkSetURI("https://auth.example.com/.well-known/jwks.json").
				IssuerURI("https://auth.example.com").
				Build()
			providerJwks := NewOAuth2LoginAuthenticationProvider(oidcServer.Client(), nil, nil)
			dec1 := providerJwks.GetOrCreateDecoderForTest(regJwks)
			Expect(dec1).NotTo(BeNil())
			dec2 := providerJwks.GetOrCreateDecoderForTest(regJwks)
			Expect(dec2).To(BeIdenticalTo(dec1))

			// Injected decoder takes precedence over JWKS URI
			providerInjected := NewOAuth2LoginAuthenticationProvider(oidcServer.Client(), nil, nil).WithJwtDecoder(decoder)
			decInjected := providerInjected.GetOrCreateDecoderForTest(regJwks)
			Expect(decInjected).To(BeIdenticalTo(decoder))
		})

		It("tests DefaultOAuth2UserService with no UserInfoURI, error response and attribute fallback", func() {
			svc := NewDefaultOAuth2UserService(nil)

			// No UserInfoURI returns error
			regNoUI := ClientRegistrationBuilder{}.New("no-ui").
				ClientID("client-no-ui").
				Build()
			reqNoUI := &OAuth2UserRequest{
				ClientRegistration: regNoUI,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), []string{"read"}),
			}
			_, err := svc.LoadUser(reqNoUI)
			Expect(err).To(HaveOccurred())

			// Error response from UserInfo endpoint
			errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer errServer.Close()

			regErr := ClientRegistrationBuilder{}.New("err-ui").
				ClientID("client-err").
				UserInfoURI(errServer.URL).
				Build()
			svcErr := NewDefaultOAuth2UserService(errServer.Client())
			_, err = svcErr.LoadUser(&OAuth2UserRequest{
				ClientRegistration: regErr,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), []string{"read"}),
			})
			Expect(err).To(HaveOccurred())

			// Attribute fallback to "login"
			githubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"login": "mona-lisa",
				})).To(Succeed())
			}))
			defer githubServer.Close()

			regGH := ClientRegistrationBuilder{}.New("github-ui").
				ClientID("client-gh").
				UserInfoURI(githubServer.URL).
				Build()
			svcGH := NewDefaultOAuth2UserService(githubServer.Client())
			userGH, err := svcGH.LoadUser(&OAuth2UserRequest{
				ClientRegistration: regGH,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), []string{"read"}),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(userGH.GetName()).To(Equal("mona-lisa"))
		})

		It("tests OAuth2LoginAuthenticationFilter edge cases: path mismatch, state CSRF mismatch, custom redirect, AuthenticationRequired", func() {
			reg := ClientRegistrationBuilder{}.New("test-filter-reg").
				ClientID("client-123").
				Build()
			repo := NewInMemoryClientRegistrationRepository(reg)
			authReqRepo := NewSessionAuthorizationRequestRepository()

			filter := NewOAuth2LoginAuthenticationFilter(
				repo,
				nil,
				nil,
			)

			// 1. Path does not match loginProcessingURL -> Next()
			otherURL, err := url.Parse("https://app.example.com/other-path")
			Expect(err).NotTo(HaveOccurred())
			hOther := NewMockSecurityHandler(HttpMethods.GET, otherURL)
			ex := filter.Authenticate(hOther)
			Expect(ex).To(HaveOccurred())
			Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))

			// 2. State mismatch / CSRF detected
			callbackURL, err := url.Parse("https://app.example.com/login/oauth2/code/test-filter-reg?code=some-code&state=bad-state")
			Expect(err).NotTo(HaveOccurred())
			hMismatch := NewMockSecurityHandler(HttpMethods.GET, callbackURL)
			// Save request in session with different state
			authReqRepo.SaveAuthorizationRequest(&OAuth2AuthorizationRequest{
				State:       "expected-state",
				RedirectURI: "https://app.example.com/callback",
			}, hMismatch)

			ex = filter.Authenticate(hMismatch)
			Expect(ex).To(HaveOccurred())
			Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))

			// 3. Custom redirect URL in session on successful login
			successCallbackURL, err := url.Parse("https://app.example.com/login/oauth2/code/test-filter-reg?code=some-code&state=good-state")
			Expect(err).NotTo(HaveOccurred())
			hSuccess := NewMockSecurityHandler(HttpMethods.GET, successCallbackURL)
			hSuccess.SetSessionValue("redirect", "/user/custom-dashboard")
			authReqRepo.SaveAuthorizationRequest(&OAuth2AuthorizationRequest{
				State:       "good-state",
				RedirectURI: "https://app.example.com/callback",
			}, hSuccess)

			mockMgr := &mockAuthManager{
				authenticateFunc: func(_ Authentication) (Authentication, AuthenticationException) {
					u := NewDefaultOAuth2User(nil, map[string]any{"sub": "user-ok"}, "sub")
					return NewOAuth2AuthenticationToken(u, nil, "test-filter-reg"), nil
				},
			}
			filterWithMgr := NewOAuth2LoginAuthenticationFilter(repo, mockMgr, nil)
			exSuccess := filterWithMgr.Authenticate(hSuccess)
			Expect(exSuccess).To(HaveOccurred())
			Expect(exSuccess.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
			Expect(exSuccess.(*DefaultSecurityFilterChainException).To()).To(Equal("/user/custom-dashboard"))

			// 3b. Malicious session redirect with protocol-relative or browser-normalized path falls back to defaultSuccessURL
			for _, evilRedirect := range []string{"//evil.com", "/\\evil.com", "http://evil.com"} {
				hEvil := NewMockSecurityHandler(HttpMethods.GET, successCallbackURL)
				hEvil.SetSessionValue("redirect", evilRedirect)
				authReqRepo.SaveAuthorizationRequest(&OAuth2AuthorizationRequest{
					State:       "good-state",
					RedirectURI: "https://app.example.com/callback",
				}, hEvil)
				exEvil := filterWithMgr.Authenticate(hEvil)
				Expect(exEvil).To(HaveOccurred())
				Expect(exEvil.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
				Expect(exEvil.(*DefaultSecurityFilterChainException).To()).To(Equal("/"))
				Expect(hEvil.SessionValue("redirect")).To(BeNil())
			}

			// 4. AuthenticationRequired GET saves path to redirect
			reqURL, err := url.Parse("https://app.example.com/profile")
			Expect(err).NotTo(HaveOccurred())
			hReqGet := NewMockSecurityHandler(HttpMethods.GET, reqURL)
			exReq := filter.AuthenticationRequired(hReqGet)
			Expect(exReq).To(HaveOccurred())
			Expect(exReq.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
			Expect(hReqGet.SessionValue("redirect")).To(Equal("/profile"))

			// 4b. AuthenticationRequired rejects protocol-relative and browser-normalized paths
			for _, evilPath := range []string{"//evil.com", "/\\evil.com"} {
				uEvil := &url.URL{Path: evilPath}
				hReqEvil := NewMockSecurityHandler(HttpMethods.GET, uEvil)
				exReqEvil := filter.AuthenticationRequired(hReqEvil)
				Expect(exReqEvil).To(HaveOccurred())
				Expect(hReqEvil.SessionValue("redirect")).To(BeNil())
			}

			// 5. AuthenticationRequired POST does not save redirect
			hReqPost := NewMockSecurityHandler(HttpMethods.POST, reqURL)
			exReqPost := filter.AuthenticationRequired(hReqPost)
			Expect(exReqPost).To(HaveOccurred())
			Expect(hReqPost.SessionValue("redirect")).To(BeNil())
		})

		It("tests GenerateAuthorizationRequest and BuildAuthorizationURI edge cases", func() {
			// RedirectURI defaulting
			regNoRedirect := ClientRegistrationBuilder{}.New("auto-reg").
				ClientID("client-auto").
				AuthorizationURI("https://auth.example.com/oauth/authorize").
				Build()
			authReq, err := GenerateAuthorizationRequest(regNoRedirect)
			Expect(err).NotTo(HaveOccurred())
			Expect(authReq.RedirectURI).To(Equal("/login/oauth2/code/auto-reg"))

			// BuildAuthorizationURI with CodeChallenge and AdditionalParams
			authReq.State = "generated-state-abc"
			authReq.CodeChallenge = "pkce-challenge-123"
			authReq.CodeChallengeMethod = "S256"
			authReq.AdditionalParams = map[string]string{
				"prompt":         "consent",
				"state":          "malicious-override-state",
				"code_challenge": "malicious-override-pkce",
			}
			builtURI := BuildAuthorizationURI(authReq)
			Expect(builtURI).To(ContainSubstring("code_challenge=pkce-challenge-123"))
			Expect(builtURI).To(ContainSubstring("state=generated-state-abc"))
			Expect(builtURI).NotTo(ContainSubstring("malicious-override-state"))
			Expect(builtURI).NotTo(ContainSubstring("malicious-override-pkce"))
			Expect(builtURI).To(ContainSubstring("prompt=consent"))

			// BaseURL option with sub-path prefix
			authReqBase, err := GenerateAuthorizationRequest(regNoRedirect, WithBaseURL("https://custom-auth.example.com/subapp"))
			Expect(err).NotTo(HaveOccurred())
			Expect(authReqBase.RedirectURI).To(Equal("https://custom-auth.example.com/subapp/login/oauth2/code/auto-reg"))

			// Invalid BaseURL returns error (invalid scheme, host, or parse error)
			_, errBadScheme := GenerateAuthorizationRequest(regNoRedirect, WithBaseURL("ftp://custom-auth.example.com"))
			Expect(errBadScheme).To(HaveOccurred())
			_, errBadHost := GenerateAuthorizationRequest(regNoRedirect, WithBaseURL("https://invalid host/subapp"))
			Expect(errBadHost).To(HaveOccurred())

			// Untrusted forwarded headers and raw Host header ignored when BaseURL is empty
			uDummy, pErr := url.Parse("http://internal-host/oauth2/authorization/auto-reg")
			Expect(pErr).NotTo(HaveOccurred())
			hUntrusted := NewMockSecurityHandler(HttpMethods.GET, uDummy)
			hUntrusted.SetHeader("X-Forwarded-Proto", "https")
			hUntrusted.SetHeader("X-Forwarded-Host", "attacker.example.com")
			authReqUntrusted, err := GenerateAuthorizationRequest(regNoRedirect, hUntrusted)
			Expect(err).NotTo(HaveOccurred())
			// Does not derive from raw Host or un-trusted proxy; remains relative
			Expect(authReqUntrusted.RedirectURI).To(Equal("/login/oauth2/code/auto-reg"))

			// Trusted proxy enabled respects forwarded headers
			authReqTrusted, err := GenerateAuthorizationRequest(regNoRedirect, hUntrusted, WithTrustedProxy(true))
			Expect(err).NotTo(HaveOccurred())
			Expect(authReqTrusted.RedirectURI).To(Equal("https://attacker.example.com/login/oauth2/code/auto-reg"))

			// Trusted proxy rejects invalid forwarded host (injection attempt) without falling back to raw Host
			hBadHost := NewMockSecurityHandler(HttpMethods.GET, uDummy)
			hBadHost.SetHeader("X-Forwarded-Host", "evil.com/payload?foo=bar")
			authReqBadHost, err := GenerateAuthorizationRequest(regNoRedirect, hBadHost, WithTrustedProxy(true))
			Expect(err).NotTo(HaveOccurred())
			// Invalid host is ignored, remains relative
			Expect(authReqBadHost.RedirectURI).To(Equal("/login/oauth2/code/auto-reg"))

			// Invalid authorization URI
			authReqBad := &OAuth2AuthorizationRequest{AuthorizationURI: "://invalid-uri"}
			Expect(BuildAuthorizationURI(authReqBad)).To(Equal("://invalid-uri"))
		})

		It("tests RegisterSecurityEndpoint authorization initiation flow and 404 on unknown ID", func() {
			reg := ClientRegistrationBuilder{}.New("init-reg").
				ClientID("client-init").
				AuthorizationURI("https://auth.example.com/oauth/authorize").
				Build()
			repo := NewInMemoryClientRegistrationRepository(reg)
			filter := NewOAuth2LoginAuthenticationFilter(repo, nil, nil).WithBaseURL("https://app.example.com")

			router := NewMockSecurityRouter()
			filter.RegisterSecurityEndpoint(router)

			// 1. Valid initiation request redirects to IdP
			initURL, err := url.Parse("https://app.example.com/oauth2/authorization/init-reg")
			Expect(err).NotTo(HaveOccurred())
			hInit := NewMockSecurityHandler(HttpMethods.GET, initURL)
			err = router.Execute(hInit)
			Expect(err).To(HaveOccurred())
			redirectEx := &DefaultSecurityFilterChainException{}
			Expect(errors.As(err, &redirectEx)).To(BeTrue())
			Expect(redirectEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
			Expect(redirectEx.To()).To(ContainSubstring("redirect_uri=" + url.QueryEscape("https://app.example.com/login/oauth2/code/init-reg")))

			// 2. Unknown registration ID returns 404 error
			initBadURL, err := url.Parse("https://app.example.com/oauth2/authorization/unknown-reg")
			Expect(err).NotTo(HaveOccurred())
			hInitBad := NewMockSecurityHandler(HttpMethods.GET, initBadURL)
			err = router.Execute(hInitBad)
			Expect(err).To(HaveOccurred())
			Expect(errors.As(err, &redirectEx)).To(BeTrue())
			Expect(redirectEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))

			// 3. Unrelated path calls Next()
			otherURL, err := url.Parse("https://app.example.com/other-route")
			Expect(err).NotTo(HaveOccurred())
			hOther := NewMockSecurityHandler(HttpMethods.GET, otherURL)
			Expect(router.Execute(hOther)).To(Succeed())
		})

		It("tests ClientAuthMethodPost, transport failure, and malformed UserInfo JSON", func() {
			// 1. ClientAuthMethodPost
			postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/userinfo" {
					Expect(json.NewEncoder(w).Encode(map[string]any{
						"sub": "post-user",
					})).To(Succeed())
					return
				}
				Expect(r.ParseForm()).To(Succeed())
				Expect(r.Form.Get("client_id")).To(Equal("post-client-id"))
				Expect(r.Form.Get("client_secret")).To(Equal("post-client-sec"))
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "post-at-123",
					"token_type":   "Bearer",
					"expires_in":   0, // tests ExpiresIn <= 0
				})).To(Succeed())
			}))
			defer postServer.Close()

			regPost := ClientRegistrationBuilder{}.New("post-reg").
				ClientID("post-client-id").
				ClientSecret("post-client-sec").
				ClientAuthenticationMethod(ClientAuthMethodPost).
				TokenURI(postServer.URL).
				UserInfoURI(postServer.URL + "/userinfo").
				Build()

			postExchange := OAuth2AuthorizationExchange{
				AuthorizationRequest:  &OAuth2AuthorizationRequest{ClientID: "post-client-id", RedirectURI: "/callback"},
				AuthorizationResponse: &OAuth2AuthorizationResponse{Code: "post-code"},
			}
			providerPost := NewOAuth2LoginAuthenticationProvider(postServer.Client(), nil, nil)
			authPost, authEx := providerPost.Authenticate(NewOAuth2LoginAuthenticationToken(regPost, postExchange))
			Expect(authEx).NotTo(HaveOccurred())
			Expect(authPost.IsAuthenticated()).To(BeTrue())

			// 2. Network transport failure via failingRoundTripper
			failingClient := &http.Client{Transport: &loginFailingRoundTripper{}}
			failingUserSvc := NewDefaultOAuth2UserService(failingClient)
			regWithUI := ClientRegistrationBuilder{}.New("failing-reg").
				ClientID("client-fail").
				UserInfoURI("http://127.0.0.1:9999/userinfo").
				Build()
			_, err := failingUserSvc.LoadUser(&OAuth2UserRequest{
				ClientRegistration: regWithUI,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), nil),
			})
			Expect(err).To(HaveOccurred())

			// 3. Malformed JSON on UserInfo endpoint
			badJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, writeErr := w.Write([]byte("{invalid-json"))
				Expect(writeErr).NotTo(HaveOccurred())
			}))
			defer badJSONServer.Close()

			regBadJSON := ClientRegistrationBuilder{}.New("bad-json-reg").
				ClientID("c-bad").
				UserInfoURI(badJSONServer.URL).
				Build()
			badJSONSvc := NewDefaultOAuth2UserService(badJSONServer.Client())
			_, err = badJSONSvc.LoadUser(&OAuth2UserRequest{
				ClientRegistration: regBadJSON,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), nil),
			})
			Expect(err).To(HaveOccurred())

			// 4. DI injection & PostConstruct on OAuth2LoginAuthenticationProvider
			provDI := &OAuth2LoginAuthenticationProvider{}
			mockUserSvc := NewDefaultOAuth2UserService(nil)
			mockOidcUserSvc := NewDefaultOidcUserService(mockUserSvc)
			provDI.SetInjectedUserServiceForTest(mockUserSvc)
			provDI.SetInjectedOidcUserServiceForTest(mockOidcUserSvc)
			Expect(provDI.PostConstruct()).To(Succeed())
			Expect(provDI.GetUserServiceForTest()).To(Equal(mockUserSvc))
			Expect(provDI.GetOidcUserServiceForTest()).To(Equal(mockOidcUserSvc))

			// PostConstruct with defaults when no injected services
			provDef := &OAuth2LoginAuthenticationProvider{}
			Expect(provDef.PostConstruct()).To(Succeed())
			Expect(provDef.GetUserServiceForTest()).NotTo(BeNil())
			Expect(provDef.GetOidcUserServiceForTest()).NotTo(BeNil())

			// 5. OAuth2LoginAuthenticationProvider.Authenticate error branches
			// Not an OAuth2LoginAuthenticationToken
			_, nonTokErr := provDef.Authenticate(&mockSimpleAuth{})
			Expect(nonTokErr).To(HaveOccurred())

			// Authorization error from IdP
			errExchange := OAuth2AuthorizationExchange{
				AuthorizationRequest:  &OAuth2AuthorizationRequest{ClientID: "c1", RedirectURI: "/cb"},
				AuthorizationResponse: &OAuth2AuthorizationResponse{Error: "access_denied", ErrorDesc: "User denied consent"},
			}
			regErr := ClientRegistrationBuilder{}.New("reg-err").ClientID("c1").Build()
			_, idpErr := provDef.Authenticate(NewOAuth2LoginAuthenticationToken(regErr, errExchange))
			Expect(idpErr).To(HaveOccurred())

			// Token exchange HTTP status error (e.g. 400 Bad Request)
			status400Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			}))
			defer status400Server.Close()
			reg400 := ClientRegistrationBuilder{}.New("reg-400").
				ClientID("c400").
				TokenURI(status400Server.URL).
				Build()
			validExchange := OAuth2AuthorizationExchange{
				AuthorizationRequest:  &OAuth2AuthorizationRequest{ClientID: "c400", RedirectURI: "/cb"},
				AuthorizationResponse: &OAuth2AuthorizationResponse{Code: "code-400"},
			}
			prov400 := NewOAuth2LoginAuthenticationProvider(status400Server.Client(), nil, nil)
			_, exch400Err := prov400.Authenticate(NewOAuth2LoginAuthenticationToken(reg400, validExchange))
			Expect(exch400Err).To(HaveOccurred())

			// Token exchange bad JSON response
			badJSONTokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, writeErr := w.Write([]byte("{invalid-json"))
				Expect(writeErr).NotTo(HaveOccurred())
			}))
			defer badJSONTokenServer.Close()
			regBadTok := ClientRegistrationBuilder{}.New("reg-bad-tok").
				ClientID("cbad").
				TokenURI(badJSONTokenServer.URL).
				Build()
			provBadTok := NewOAuth2LoginAuthenticationProvider(badJSONTokenServer.Client(), nil, nil)
			_, exchBadJSONErr := provBadTok.Authenticate(NewOAuth2LoginAuthenticationToken(regBadTok, validExchange))
			Expect(exchBadJSONErr).To(HaveOccurred())

			// OIDC UserService failure during Authenticate
			goodTokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "at-good",
					"token_type":   "Bearer",
					"expires_in":   3600,
					"scope":        "openid profile",
				})).To(Succeed())
			}))
			defer goodTokenServer.Close()
			regOidcFail := ClientRegistrationBuilder{}.New("reg-oidc-fail").
				ClientID("c-oidc").
				TokenURI(goodTokenServer.URL).
				Scope("openid").
				Build()
			provOidcFail := NewOAuth2LoginAuthenticationProvider(goodTokenServer.Client(), nil, &failingOidcUserService{})
			_, oidcFailErr := provOidcFail.Authenticate(NewOAuth2LoginAuthenticationToken(regOidcFail, validExchange))
			Expect(oidcFailErr).To(HaveOccurred())

			// OAuth2 UserService failure during Authenticate (non-OIDC)
			goodNonOidcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "at-good",
					"token_type":   "Bearer",
					"expires_in":   3600,
					"scope":        "read",
				})).To(Succeed())
			}))
			defer goodNonOidcServer.Close()
			regOAuthFail := ClientRegistrationBuilder{}.New("reg-oauth-fail").
				ClientID("c-oauth").
				TokenURI(goodNonOidcServer.URL).
				Scope("read").
				Build()
			provOAuthFail := NewOAuth2LoginAuthenticationProvider(goodNonOidcServer.Client(), &failingOAuth2UserService{}, nil)
			_, oauthFailErr := provOAuthFail.Authenticate(NewOAuth2LoginAuthenticationToken(regOAuthFail, validExchange))
			Expect(oauthFailErr).To(HaveOccurred())

			// 6. OAuth2LoginAuthenticationFilter.WithContext prototype lifecycle tests
			loginFilter := &OAuth2LoginAuthenticationFilter{}
			// Non-HttpSecurity in context
			badCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, "not-http-security")
			Expect(loginFilter.WithContext(badCtx)).To(HaveOccurred())

			// HttpSecurity without oAuth2LoginAuthenticationFilter in SecurityFilters
			emptySec := (&HttpSecurityBuilder{}).Build()
			emptyCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, emptySec)
			Expect(loginFilter.WithContext(emptyCtx)).To(HaveOccurred())

			// HttpSecurity with invalid config type
			badCfgSec := (&HttpSecurityBuilder{}).AddCustomSecurityFilter("oAuth2LoginAuthenticationFilter", "invalid-config-type").Build()
			badCfgCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, badCfgSec)
			Expect(loginFilter.WithContext(badCfgCtx)).To(HaveOccurred())

			// Injected dependencies in filter
			filterWithDeps := &OAuth2LoginAuthenticationFilter{}
			filterWithDeps.SetInjectedDepsForTest(
				InMemoryClientRegistrationRepository{}.New(regOidcFail),
				SessionAuthorizationRequestRepository{}.New(),
				&mockAuthManager{},
				&mockSecurityContextHolder{},
			)
			validSec := (&HttpSecurityBuilder{}).AddCustomSecurityFilter("oAuth2LoginAuthenticationFilter", &OAuth2LoginConfig{}).Build()
			validCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, validSec)
			Expect(filterWithDeps.WithContext(validCtx)).To(Succeed())

			// 7. DefaultOAuth2UserService & DefaultOidcUserService attribute fallback tests
			// UserInfo returns 401 Unauthorized
			unauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}))
			defer unauthServer.Close()
			regUnauth := ClientRegistrationBuilder{}.New("reg-unauth").
				ClientID("c-unauth").
				UserInfoURI(unauthServer.URL).
				Build()
			unauthSvc := NewDefaultOAuth2UserService(unauthServer.Client())
			_, unauthErr := unauthSvc.LoadUser(&OAuth2UserRequest{
				ClientRegistration: regUnauth,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), nil),
			})
			Expect(unauthErr).To(HaveOccurred())

			// UserInfo returns "id" claim fallback (GitHub style)
			idServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{"id": "github-123456", "name": "Github User"})).To(Succeed())
			}))
			defer idServer.Close()
			regID := ClientRegistrationBuilder{}.New("reg-id").
				ClientID("c-id").
				UserInfoURI(idServer.URL).
				Build()
			idSvc := NewDefaultOAuth2UserService(idServer.Client())
			idUser, err := idSvc.LoadUser(&OAuth2UserRequest{
				ClientRegistration: regID,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), []string{"read"}),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(idUser.GetName()).To(Equal("github-123456"))

			// UserInfo returns "login" claim fallback
			loginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{"login": "octocat"})).To(Succeed())
			}))
			defer loginServer.Close()
			regLogin := ClientRegistrationBuilder{}.New("reg-login").
				ClientID("c-login").
				UserInfoURI(loginServer.URL).
				Build()
			loginSvc := NewDefaultOAuth2UserService(loginServer.Client())
			loginUser, err := loginSvc.LoadUser(&OAuth2UserRequest{
				ClientRegistration: regLogin,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), nil),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(loginUser.GetName()).To(Equal("octocat"))

			// OIDC UserService when UserInfoURI fails: still returns OidcUser with ID token claims
			failingOidcUserSvc := NewDefaultOidcUserService(&failingOAuth2UserService{})
			regOidcWithUI := ClientRegistrationBuilder{}.New("reg-oidc-with-ui").
				ClientID("c-oidc-ui").
				UserInfoURI("http://127.0.0.1:9999/userinfo").
				Build()
			oidcUserWithFallback, err := failingOidcUserSvc.LoadUser(&OidcUserRequest{
				ClientRegistration: regOidcWithUI,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), nil),
				IdToken:            &OidcIdToken{TokenValue: "id-tok", Claims: map[string]any{"sub": "sub-123"}},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(oidcUserWithFallback.GetName()).To(Equal("sub-123"))

			// OIDC UserService rejects missing or empty user name attribute
			regOidcNoName := ClientRegistrationBuilder{}.New("reg-oidc-no-name").
				ClientID("c-oidc-no-name").
				Build()
			_, err = failingOidcUserSvc.LoadUser(&OidcUserRequest{
				ClientRegistration: regOidcNoName,
				AccessToken:        OAuth2AccessToken{}.New(TokenTypeBearer, "tok", time.Now(), time.Now().Add(time.Hour), nil),
				IdToken:            &OidcIdToken{TokenValue: "id-tok", Claims: map[string]any{}},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("InvalidUserError"))
		})
	})
})

type loginFailingRoundTripper struct{}

func (this *loginFailingRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network connection failure")
}

type failingOAuth2UserService struct{}

func (this *failingOAuth2UserService) LoadUser(_ *OAuth2UserRequest) (OAuth2User, Error) {
	return nil, NewError("LoadOAuth2UserFailed", "load oauth2 user error")
}

type failingOidcUserService struct{}

func (this *failingOidcUserService) LoadUser(_ *OidcUserRequest) (OidcUser, Error) {
	return nil, NewError("LoadOidcUserFailed", "load oidc user error")
}

type mockSimpleAuth struct{}

func (this *mockSimpleAuth) GetAuthorities() []GrantedAuthority { return nil }
func (this *mockSimpleAuth) GetCredentials() any                { return nil }
func (this *mockSimpleAuth) GetDetails() any                    { return nil }
func (this *mockSimpleAuth) GetPrincipal() any                  { return nil }
func (this *mockSimpleAuth) IsAuthenticated() bool              { return false }
func (this *mockSimpleAuth) SetAuthenticated(_ bool)            {}
func (this *mockSimpleAuth) GetName() string                    { return "simple" }
