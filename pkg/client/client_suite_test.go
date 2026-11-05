// Package client_test contains unit tests for OAuth 2.0 client registration repositories, authorized client services, and managers.
package client_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
	_ "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// TestClient runs the Ginkgo test suite for the OAuth2 client package.
func TestClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OAuth2 Client Suite")
}

var _ = Describe("InMemoryClientRegistrationRepository", func() {
	It("stores and retrieves client registrations", func() {
		reg1 := ClientRegistrationBuilder{}.New("google").
			ClientID("google-id").
			ClientSecret("google-sec").
			Build()
		reg2 := ClientRegistrationBuilder{}.New("github").
			ClientID("github-id").
			ClientSecret("github-sec").
			Build()

		repo := InMemoryClientRegistrationRepository{}.New(reg1)
		found, err := repo.FindByRegistrationID("google")
		Expect(err).NotTo(HaveOccurred())
		Expect(found.ClientID).To(Equal("google-id"))

		_, err = repo.FindByRegistrationID("github")
		Expect(err).To(HaveOccurred())

		repo.Add(reg2)
		found2, err := repo.FindByRegistrationID("github")
		Expect(err).NotTo(HaveOccurred())
		Expect(found2.ClientID).To(Equal("github-id"))
	})
})

var _ = Describe("InMemoryOAuth2AuthorizedClientService", func() {
	It("saves, loads, and removes authorized clients", func() {
		reg := ClientRegistrationBuilder{}.New("salesforce").
			ClientID("sf-client").
			Build()
		now := time.Now()
		accessToken := OAuth2AccessToken{}.New(TokenTypeBearer, "token-sf", now, now.Add(time.Hour), []string{"api"})
		refreshToken := OAuth2RefreshToken{}.New("refresh-sf", now, time.Time{})

		authorizedClient := OAuth2AuthorizedClient{}.New(reg, "john", accessToken, refreshToken)
		service := InMemoryOAuth2AuthorizedClientService{}.New()

		// Before saving
		_, err := service.LoadAuthorizedClient("salesforce", "john")
		Expect(err).To(HaveOccurred())

		// After saving
		err = service.SaveAuthorizedClient(authorizedClient)
		Expect(err).NotTo(HaveOccurred())

		loaded, err := service.LoadAuthorizedClient("salesforce", "john")
		Expect(err).NotTo(HaveOccurred())
		Expect(loaded.AccessToken.TokenValue).To(Equal("token-sf"))
		Expect(loaded.RefreshToken.TokenValue).To(Equal("refresh-sf"))

		// Remove
		err = service.RemoveAuthorizedClient("salesforce", "john")
		Expect(err).NotTo(HaveOccurred())

		_, err = service.LoadAuthorizedClient("salesforce", "john")
		Expect(err).To(HaveOccurred())
	})

	It("prevents key collisions when registration ID or principal name contain delimiters", func() {
		reg1 := ClientRegistrationBuilder{}.New("app::user").ClientID("c1").Build()
		reg2 := ClientRegistrationBuilder{}.New("app").ClientID("c2").Build()
		now := time.Now()
		tok1 := OAuth2AccessToken{}.New(TokenTypeBearer, "token-1", now, now.Add(time.Hour), nil)
		tok2 := OAuth2AccessToken{}.New(TokenTypeBearer, "token-2", now, now.Add(time.Hour), nil)

		client1 := OAuth2AuthorizedClient{}.New(reg1, "one", tok1, nil)
		client2 := OAuth2AuthorizedClient{}.New(reg2, "user::one", tok2, nil)

		service := InMemoryOAuth2AuthorizedClientService{}.New()
		Expect(service.SaveAuthorizedClient(client1)).To(Succeed())
		Expect(service.SaveAuthorizedClient(client2)).To(Succeed())

		loaded1, err1 := service.LoadAuthorizedClient("app::user", "one")
		Expect(err1).NotTo(HaveOccurred())
		Expect(loaded1.AccessToken.TokenValue).To(Equal("token-1"))

		loaded2, err2 := service.LoadAuthorizedClient("app", "user::one")
		Expect(err2).NotTo(HaveOccurred())
		Expect(loaded2.AccessToken.TokenValue).To(Equal("token-2"))
	})
})

var _ = Describe("Authorized Client Providers & Manager", func() {
	var mockServer *httptest.Server

	AfterEach(func() {
		if mockServer != nil {
			mockServer.Close()
		}
	})

	Context("RefreshTokenAuthorizedClientProvider", func() {
		It("detects expired tokens and refreshes them via Token Endpoint", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodPost))
				Expect(r.Header.Get("Content-Type")).To(Equal("application/x-www-form-urlencoded"))
				u, p, ok := r.BasicAuth()
				Expect(ok).To(BeTrue())
				Expect(u).To(Equal("my-client-id"))
				Expect(p).To(Equal("my-secret"))

				err := r.ParseForm()
				Expect(err).NotTo(HaveOccurred())
				Expect(r.Form.Get("grant_type")).To(Equal("refresh_token"))
				Expect(r.Form.Get("refresh_token")).To(Equal("existing-refresh-token"))

				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "new-refreshed-access-token",
					"token_type":    "Bearer",
					"expires_in":    3600,
					"refresh_token": "updated-refresh-token",
					"scope":         "read write",
				})).To(Succeed())
			}))

			reg := ClientRegistrationBuilder{}.New("test-provider").
				ClientID("my-client-id").
				ClientSecret("my-secret").
				TokenURI(mockServer.URL).
				Build()

			now := time.Now()
			expiredToken := OAuth2AccessToken{}.New(TokenTypeBearer, "old-token", now.Add(-2*time.Hour), now.Add(-1*time.Hour), []string{"read"})
			refreshToken := OAuth2RefreshToken{}.New("existing-refresh-token", now.Add(-2*time.Hour), time.Time{})

			existingAuthorizedClient := OAuth2AuthorizedClient{}.New(reg, "alice", expiredToken, refreshToken)

			provider := RefreshTokenAuthorizedClientProvider{}.New(mockServer.Client())
			req := &OAuth2AuthorizeRequest{
				ClientRegistration: reg,
				PrincipalName:      "alice",
				AuthorizedClient:   existingAuthorizedClient,
			}

			Expect(provider.Supports(req)).To(BeTrue())

			refreshed, err := provider.Authorize(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(refreshed).NotTo(BeNil())
			Expect(refreshed.AccessToken.TokenValue).To(Equal("new-refreshed-access-token"))
			Expect(refreshed.RefreshToken.TokenValue).To(Equal("updated-refresh-token"))
			Expect(refreshed.AccessToken.Scopes).To(ConsistOf("read", "write"))
		})

		It("refreshes token using ClientAuthMethodPost", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodPost))
				_, _, ok := r.BasicAuth()
				Expect(ok).To(BeFalse())

				err := r.ParseForm()
				Expect(err).NotTo(HaveOccurred())
				Expect(r.Form.Get("grant_type")).To(Equal("refresh_token"))
				Expect(r.Form.Get("refresh_token")).To(Equal("existing-rf-token"))
				Expect(r.Form.Get("client_id")).To(Equal("post-client-id"))
				Expect(r.Form.Get("client_secret")).To(Equal("post-secret"))

				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "post-refreshed-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})).To(Succeed())
			}))

			reg := ClientRegistrationBuilder{}.New("test-post-rf").
				ClientID("post-client-id").
				ClientSecret("post-secret").
				ClientAuthenticationMethod(ClientAuthMethodPost).
				TokenURI(mockServer.URL).
				Build()

			now := time.Now()
			expiredToken := OAuth2AccessToken{}.New(TokenTypeBearer, "old-token", now.Add(-2*time.Hour), now.Add(-1*time.Hour), []string{"read"})
			refreshToken := OAuth2RefreshToken{}.New("existing-rf-token", now.Add(-2*time.Hour), time.Time{})
			existingAuthorizedClient := OAuth2AuthorizedClient{}.New(reg, "bob", expiredToken, refreshToken)

			provider := RefreshTokenAuthorizedClientProvider{}.New(mockServer.Client())
			req := &OAuth2AuthorizeRequest{
				ClientRegistration: reg,
				PrincipalName:      "bob",
				AuthorizedClient:   existingAuthorizedClient,
			}

			refreshed, err := provider.Authorize(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(refreshed.AccessToken.TokenValue).To(Equal("post-refreshed-token"))
		})
	})

	Context("ClientCredentialsAuthorizedClientProvider", func() {
		It("obtains access token via client_credentials grant", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodPost))
				u, p, ok := r.BasicAuth()
				Expect(ok).To(BeTrue())
				Expect(u).To(Equal("service-worker"))
				Expect(p).To(Equal("service-sec"))

				err := r.ParseForm()
				Expect(err).NotTo(HaveOccurred())
				Expect(r.Form.Get("grant_type")).To(Equal("client_credentials"))
				Expect(r.Form.Get("scope")).To(Equal("internal-metrics audit"))

				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "m2m-access-token-12345",
					"token_type":   "Bearer",
					"expires_in":   7200,
				})).To(Succeed())
			}))

			reg := ClientRegistrationBuilder{}.New("backend-service").
				ClientID("service-worker").
				ClientSecret("service-sec").
				AuthorizationGrantType(GrantTypeClientCredentials).
				TokenURI(mockServer.URL).
				Scope("internal-metrics", "audit").
				Build()

			provider := ClientCredentialsAuthorizedClientProvider{}.New(mockServer.Client())
			req := &OAuth2AuthorizeRequest{
				ClientRegistration: reg,
				PrincipalName:      "backend-service",
			}

			Expect(provider.Supports(req)).To(BeTrue())

			authorized, err := provider.Authorize(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(authorized).NotTo(BeNil())
			Expect(authorized.AccessToken.TokenValue).To(Equal("m2m-access-token-12345"))
			Expect(authorized.AccessToken.Scopes).To(ConsistOf("internal-metrics", "audit"))
		})

		It("obtains access token using ClientAuthMethodPost", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodPost))
				_, _, ok := r.BasicAuth()
				Expect(ok).To(BeFalse())

				err := r.ParseForm()
				Expect(err).NotTo(HaveOccurred())
				Expect(r.Form.Get("grant_type")).To(Equal("client_credentials"))
				Expect(r.Form.Get("client_id")).To(Equal("post-cc-id"))
				Expect(r.Form.Get("client_secret")).To(Equal("post-cc-secret"))

				w.Header().Set("Content-Type", "application/json")
				//nolint:gosec // mock token in test
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "post-cc-token",
					"token_type":   "Bearer",
					"expires_in":   7200,
				})).To(Succeed())
			}))

			reg := ClientRegistrationBuilder{}.New("backend-post-cc").
				ClientID("post-cc-id").
				ClientSecret("post-cc-secret").
				ClientAuthenticationMethod(ClientAuthMethodPost).
				AuthorizationGrantType(GrantTypeClientCredentials).
				TokenURI(mockServer.URL).
				Build()

			provider := ClientCredentialsAuthorizedClientProvider{}.New(mockServer.Client())
			req := &OAuth2AuthorizeRequest{
				ClientRegistration: reg,
				PrincipalName:      "backend-post-cc",
			}

			authorized, err := provider.Authorize(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(authorized.AccessToken.TokenValue).To(Equal("post-cc-token"))
		})
	})

	Context("DefaultOAuth2AuthorizedClientManager", func() {
		It("orchestrates loading, refreshing, and saving authorized client", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "managed-refreshed-token",
					"token_type":   "Bearer",
					"expires_in":   1800,
				})).To(Succeed())
			}))

			reg := ClientRegistrationBuilder{}.New("auth0").
				ClientID("auth0-client").
				ClientSecret("auth0-secret").
				TokenURI(mockServer.URL).
				Build()

			regRepo := InMemoryClientRegistrationRepository{}.New(reg)
			clientService := InMemoryOAuth2AuthorizedClientService{}.New()

			now := time.Now()
			expiredToken := OAuth2AccessToken{}.New(TokenTypeBearer, "old-tok", now.Add(-time.Hour), now.Add(-10*time.Minute), []string{"read"})
			refreshToken := OAuth2RefreshToken{}.New("saved-refresh-tok", now.Add(-time.Hour), time.Time{})
			existingClient := OAuth2AuthorizedClient{}.New(reg, "carol", expiredToken, refreshToken)

			err := clientService.SaveAuthorizedClient(existingClient)
			Expect(err).NotTo(HaveOccurred())

			manager := DefaultOAuth2AuthorizedClientManager{}.New(
				regRepo,
				clientService,
				RefreshTokenAuthorizedClientProvider{}.New(mockServer.Client()),
			)

			// Authorize request using ClientRegistration and PrincipalName
			result, err := manager.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: reg,
				PrincipalName:      "carol",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.AccessToken.TokenValue).To(Equal("managed-refreshed-token"))

			// Verify it was updated in the repository
			saved, err := clientService.LoadAuthorizedClient("auth0", "carol")
			Expect(err).NotTo(HaveOccurred())
			Expect(saved.AccessToken.TokenValue).To(Equal("managed-refreshed-token"))
		})

		It("returns error when SaveAuthorizedClient fails in manager", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "token-to-save",
					"token_type":   "Bearer",
					"expires_in":   1800,
				})).To(Succeed())
			}))

			reg := ClientRegistrationBuilder{}.New("auth0-fail").
				ClientID("auth0-client").
				ClientSecret("auth0-secret").
				TokenURI(mockServer.URL).
				Build()

			regRepo := InMemoryClientRegistrationRepository{}.New(reg)
			failingService := &testFailingAuthorizedClientService{}

			now := time.Now()
			expiredToken := OAuth2AccessToken{}.New(TokenTypeBearer, "old-tok", now.Add(-time.Hour), now.Add(-10*time.Minute), []string{"read"})
			refreshToken := OAuth2RefreshToken{}.New("saved-refresh-tok", now.Add(-time.Hour), time.Time{})
			existingClient := OAuth2AuthorizedClient{}.New(reg, "carol", expiredToken, refreshToken)

			manager := DefaultOAuth2AuthorizedClientManager{}.New(
				regRepo,
				failingService,
				RefreshTokenAuthorizedClientProvider{}.New(mockServer.Client()),
			)

			result, err := manager.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: reg,
				PrincipalName:      "carol",
				AuthorizedClient:   existingClient,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("StorageSaveError"))
			Expect(result).To(BeNil())
		})

		It("returns existing authorized client early if access token is still valid", func() {
			reg := ClientRegistrationBuilder{}.New("auth-code-client").
				ClientID("client-id").
				AuthorizationGrantType(GrantTypeAuthorizationCode).
				Build()

			now := time.Now()
			validToken := OAuth2AccessToken{}.New(TokenTypeBearer, "valid-cached-token", now, now.Add(30*time.Minute), []string{"read"})
			existingClient := OAuth2AuthorizedClient{}.New(reg, "alice", validToken, nil)

			manager := DefaultOAuth2AuthorizedClientManager{}.New(nil, nil)

			result, err := manager.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: reg,
				PrincipalName:      "alice",
				AuthorizedClient:   existingClient,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(existingClient))
			Expect(result.AccessToken.TokenValue).To(Equal("valid-cached-token"))
		})

		It("tests constructors, unsupported requests and error responses from token endpoints", func() {
			reg := ClientRegistrationBuilder{}.New("test-client").
				ClientID("cid").
				ClientSecret("csec").
				TokenURI("http://invalid.local/token").
				Build()

			repo := NewInMemoryClientRegistrationRepository(reg)
			Expect(repo).NotTo(BeNil())

			service := NewInMemoryOAuth2AuthorizedClientService()
			Expect(service).NotTo(BeNil())

			ccProvider := NewClientCredentialsAuthorizedClientProvider(nil)
			Expect(ccProvider).NotTo(BeNil())

			rfProvider := NewRefreshTokenAuthorizedClientProvider(nil)
			Expect(rfProvider).NotTo(BeNil())

			manager := NewDefaultOAuth2AuthorizedClientManager(repo, service, ccProvider, rfProvider)
			Expect(manager).NotTo(BeNil())

			// Unsupported request
			unsupportedReq := &OAuth2AuthorizeRequest{
				ClientRegistration: ClientRegistrationBuilder{}.New("unsupported").
					AuthorizationGrantType(AuthorizationGrantType("unknown")).
					Build(),
			}
			_, err := manager.Authorize(unsupportedReq)
			Expect(err).To(HaveOccurred())

			// Error response from server for ClientCredentials
			errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, writeErr := w.Write([]byte(`{"error":"invalid_client"}`))
				Expect(writeErr).NotTo(HaveOccurred())
			}))
			defer errServer.Close()

			regWithErrServer := ClientRegistrationBuilder{}.New("err-reg").
				ClientID("bad-client").
				AuthorizationGrantType(GrantTypeClientCredentials).
				TokenURI(errServer.URL).
				Build()

			ccProviderErr := NewClientCredentialsAuthorizedClientProvider(errServer.Client())
			_, err = ccProviderErr.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: regWithErrServer,
				PrincipalName:      "bad-client",
			})
			Expect(err).To(HaveOccurred())

			// Error response from server for RefreshToken
			rfProviderErr := NewRefreshTokenAuthorizedClientProvider(errServer.Client())
			existingClient := OAuth2AuthorizedClient{}.New(regWithErrServer, "bad-client", nil, OAuth2RefreshToken{}.New("rf-tok", time.Now(), time.Time{}))
			_, err = rfProviderErr.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: regWithErrServer,
				PrincipalName:      "bad-client",
				AuthorizedClient:   existingClient,
			})
			Expect(err).To(HaveOccurred())

			// DefaultOAuth2AuthorizedClientManager edge cases
			emptyManager := NewDefaultOAuth2AuthorizedClientManager(nil, nil)
			_, err = emptyManager.Authorize(&OAuth2AuthorizeRequest{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("client registration or registration ID is required"))

			_, err = emptyManager.Authorize(&OAuth2AuthorizeRequest{ClientRegistrationID: "some-id"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("client registration repository is not configured"))

			// Authorize by ClientRegistrationID with repo and service
			mockSuccessServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "auto-at",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})).To(Succeed())
			}))
			defer mockSuccessServer.Close()

			validReg := ClientRegistrationBuilder{}.New("reg-lookup").
				ClientID("client-1").
				ClientSecret("secret-1").
				AuthorizationGrantType(GrantTypeClientCredentials).
				TokenURI(mockSuccessServer.URL).
				Build()

			regRepo := NewInMemoryClientRegistrationRepository(validReg)
			clientSvc := NewInMemoryOAuth2AuthorizedClientService()
			fullManager := NewDefaultOAuth2AuthorizedClientManager(
				regRepo,
				clientSvc,
				NewClientCredentialsAuthorizedClientProvider(mockSuccessServer.Client()),
			)

			// Authorize by ID: manager loads reg, calls provider, and saves to service
			authClient, err := fullManager.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistrationID: "reg-lookup",
				PrincipalName:        "client-1",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(authClient.AccessToken.TokenValue).To(Equal("auto-at"))

			// Subsequent authorize loads from service
			loadedClient, err := fullManager.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistrationID: "reg-lookup",
				PrincipalName:        "client-1",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(loadedClient).NotTo(BeNil())

			// Supports edge cases
			rfProvider = NewRefreshTokenAuthorizedClientProvider(nil)
			Expect(rfProvider.Supports(&OAuth2AuthorizeRequest{})).To(BeFalse())
			Expect(rfProvider.Supports(&OAuth2AuthorizeRequest{
				AuthorizedClient: OAuth2AuthorizedClient{}.New(validReg, "u", nil, nil),
			})).To(BeFalse())

			// RefreshToken with nil access token returns true
			Expect(rfProvider.Supports(&OAuth2AuthorizeRequest{
				AuthorizedClient: OAuth2AuthorizedClient{}.New(validReg, "u", nil, OAuth2RefreshToken{}.New("rf", time.Now(), time.Time{})),
			})).To(BeTrue())

			// RefreshToken with valid unexpired token returns false
			freshToken := OAuth2AccessToken{}.New(TokenTypeBearer, "val", time.Now(), time.Now().Add(24*time.Hour), nil)
			Expect(rfProvider.Supports(&OAuth2AuthorizeRequest{
				AuthorizedClient: OAuth2AuthorizedClient{}.New(validReg, "u", freshToken, OAuth2RefreshToken{}.New("rf", time.Now(), time.Time{})),
			})).To(BeFalse())

			ccProvider = NewClientCredentialsAuthorizedClientProvider(nil)
			codeReg := ClientRegistrationBuilder{}.New("code-reg").
				AuthorizationGrantType(GrantTypeAuthorizationCode).
				Build()
			Expect(ccProvider.Supports(&OAuth2AuthorizeRequest{ClientRegistration: codeReg})).To(BeFalse())

			// Network transport error via failingRoundTripper
			failingClient := &http.Client{Transport: &clientFailingRoundTripper{}}
			ccProviderFailing := NewClientCredentialsAuthorizedClientProvider(failingClient)
			_, err = ccProviderFailing.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: regWithErrServer,
				PrincipalName:      "bad-client",
			})
			Expect(err).To(HaveOccurred())

			rfProviderFailing := NewRefreshTokenAuthorizedClientProvider(failingClient)
			_, err = rfProviderFailing.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: regWithErrServer,
				PrincipalName:      "bad-client",
				AuthorizedClient:   existingClient,
			})
			Expect(err).To(HaveOccurred())

			// Malformed JSON response body from token endpoint
			badJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, writeErr := w.Write([]byte("{invalid-json-body"))
				Expect(writeErr).NotTo(HaveOccurred())
			}))
			defer badJSONServer.Close()

			regBadJSON := ClientRegistrationBuilder{}.New("bad-json-cc").
				ClientID("client-bj").
				AuthorizationGrantType(GrantTypeClientCredentials).
				TokenURI(badJSONServer.URL).
				Build()
			ccProviderBadJSON := NewClientCredentialsAuthorizedClientProvider(badJSONServer.Client())
			_, err = ccProviderBadJSON.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: regBadJSON,
				PrincipalName:      "client-bj",
			})
			Expect(err).To(HaveOccurred())

			// Refresh token with status 400 Bad Request
			status400Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			}))
			defer status400Server.Close()

			reg400 := ClientRegistrationBuilder{}.New("reg-400-rf").
				ClientID("c400").
				TokenURI(status400Server.URL).
				Build()
			rfProvider400 := NewRefreshTokenAuthorizedClientProvider(status400Server.Client())
			_, err = rfProvider400.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: reg400,
				PrincipalName:      "user-400",
				AuthorizedClient:   existingClient,
			})
			Expect(err).To(HaveOccurred())

			// Refresh token with rotated refresh token returned in response
			rotatedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				//nolint:gosec // test token
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "new-at-val",
					"token_type":    "Bearer",
					"refresh_token": "new-rotated-rf-val",
					"expires_in":    7200,
					"scope":         "read write",
				})).To(Succeed())
			}))
			defer rotatedServer.Close()

			regRotated := ClientRegistrationBuilder{}.New("reg-rotated").
				ClientID("c-rot").
				TokenURI(rotatedServer.URL).
				Build()
			rfProviderRotated := NewRefreshTokenAuthorizedClientProvider(rotatedServer.Client())
			rotatedClient, err := rfProviderRotated.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: regRotated,
				PrincipalName:      "user-rot",
				AuthorizedClient:   existingClient,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(rotatedClient.RefreshToken.TokenValue).To(Equal("new-rotated-rf-val"))

			// Refresh token with malformed JSON
			rfProviderBadJSON := NewRefreshTokenAuthorizedClientProvider(badJSONServer.Client())
			_, err = rfProviderBadJSON.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: regBadJSON,
				PrincipalName:      "user-bj",
				AuthorizedClient:   existingClient,
			})
			Expect(err).To(HaveOccurred())

			// ClientCredentials with status 400 Bad Request
			ccProvider400 := NewClientCredentialsAuthorizedClientProvider(status400Server.Client())
			_, err = ccProvider400.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: reg400,
				PrincipalName:      "user-400",
			})
			Expect(err).To(HaveOccurred())

			// ClientCredentials Supports with nil ClientRegistration
			Expect(ccProvider.Supports(&OAuth2AuthorizeRequest{})).To(BeFalse())

			// DefaultOAuth2AuthorizedClientManager error cases
			mgr := NewDefaultOAuth2AuthorizedClientManager(nil, nil)
			_, err = mgr.Authorize(&OAuth2AuthorizeRequest{})
			Expect(err).To(HaveOccurred())

			// No provider supports the request
			codeRegNoCC := ClientRegistrationBuilder{}.New("code-only").
				AuthorizationGrantType(GrantTypeAuthorizationCode).
				Build()
			mgrNoMatch := NewDefaultOAuth2AuthorizedClientManager(
				InMemoryClientRegistrationRepository{}.New(codeRegNoCC),
				nil,
				ccProvider, // ccProvider only supports ClientCredentials
			)
			_, err = mgrNoMatch.Authorize(&OAuth2AuthorizeRequest{
				ClientRegistration: codeRegNoCC,
			})
			Expect(err).To(HaveOccurred())

			// Manager FindByRegistrationID error when repo is configured but ID not found
			emptyRepo := InMemoryClientRegistrationRepository{}.New()
			mgrWithRepo := NewDefaultOAuth2AuthorizedClientManager(emptyRepo, nil)
			_, err = mgrWithRepo.Authorize(&OAuth2AuthorizeRequest{ClientRegistrationID: "unknown-id"})
			Expect(err).To(HaveOccurred())

			// Manager provider error propagation
			failingCCProvider := NewClientCredentialsAuthorizedClientProvider(&http.Client{Transport: &clientFailingRoundTripper{}})
			mgrFailingProv := NewDefaultOAuth2AuthorizedClientManager(nil, nil, failingCCProvider)
			_, err = mgrFailingProv.Authorize(&OAuth2AuthorizeRequest{ClientRegistration: regWithErrServer})
			Expect(err).To(HaveOccurred())

			// Invalid TokenURI for RefreshToken and ClientCredentials
			badURIReg := ClientRegistrationBuilder{}.New("bad-uri-reg").
				AuthorizationGrantType(GrantTypeClientCredentials).
				TokenURI("://invalid-url\x7f").
				Build()
			_, err = rfProvider.Authorize(&OAuth2AuthorizeRequest{ClientRegistration: badURIReg, AuthorizedClient: existingClient})
			Expect(err).To(HaveOccurred())
			_, err = ccProvider.Authorize(&OAuth2AuthorizeRequest{ClientRegistration: badURIReg})
			Expect(err).To(HaveOccurred())

			// Error reading body and closing body for RefreshToken and ClientCredentials
			errBodyClient := &http.Client{Transport: &clientErrBodyRoundTripper{}}
			rfErrBody := NewRefreshTokenAuthorizedClientProvider(errBodyClient)
			_, err = rfErrBody.Authorize(&OAuth2AuthorizeRequest{ClientRegistration: regWithErrServer, AuthorizedClient: existingClient})
			Expect(err).To(HaveOccurred())

			ccErrBody := NewClientCredentialsAuthorizedClientProvider(errBodyClient)
			_, err = ccErrBody.Authorize(&OAuth2AuthorizeRequest{ClientRegistration: regWithErrServer})
			Expect(err).To(HaveOccurred())

			// ClientCredentials with scope returned in token response
			scopeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				Expect(json.NewEncoder(w).Encode(map[string]any{
					"access_token": "scoped-token",
					"token_type":   "Bearer",
					"scope":        "read write admin",
					"expires_in":   3600,
				})).To(Succeed())
			}))
			defer scopeServer.Close()
			regScoped := ClientRegistrationBuilder{}.New("scoped-reg").
				TokenURI(scopeServer.URL).
				AuthorizationGrantType(GrantTypeClientCredentials).
				Build()
			ccProviderScoped := NewClientCredentialsAuthorizedClientProvider(scopeServer.Client())
			scopedClient, err := ccProviderScoped.Authorize(&OAuth2AuthorizeRequest{ClientRegistration: regScoped})
			Expect(err).NotTo(HaveOccurred())
			Expect(scopedClient.AccessToken.Scopes).To(ConsistOf("read", "write", "admin"))
		})
	})
})

// clientFailingRoundTripper is an http.RoundTripper test double that always returns a network error.
type clientFailingRoundTripper struct{}

// RoundTrip simulates a network connection failure.
func (this *clientFailingRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network connection failure")
}

// testFailingAuthorizedClientService is an OAuth2AuthorizedClientService test double that fails on save and load.
type testFailingAuthorizedClientService struct{}

// SaveAuthorizedClient simulates a storage save error.
func (this *testFailingAuthorizedClientService) SaveAuthorizedClient(_ *OAuth2AuthorizedClient) Error {
	return NewError("StorageSaveError", "simulated save failure")
}

// LoadAuthorizedClient simulates an authorized client lookup error.
func (this *testFailingAuthorizedClientService) LoadAuthorizedClient(_, _ string) (*OAuth2AuthorizedClient, Error) {
	return nil, NewError("AuthorizedClientNotFound", "client not found")
}

// RemoveAuthorizedClient is a no-op that returns nil.
func (this *testFailingAuthorizedClientService) RemoveAuthorizedClient(_, _ string) Error {
	return nil
}

type clientErrReaderCloser struct{}

func (this *clientErrReaderCloser) Read(_ []byte) (int, error) {
	return 0, errors.New("read error")
}

func (this *clientErrReaderCloser) Close() error {
	return errors.New("close error")
}

type clientErrBodyRoundTripper struct{}

func (this *clientErrBodyRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       &clientErrReaderCloser{},
		Header:     make(http.Header),
	}, nil
}
