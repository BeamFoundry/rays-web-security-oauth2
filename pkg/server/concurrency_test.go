package server_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/server"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/web"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OAuth2 Authorization Server Concurrency & Replay Attacks", func() {
	It("strictly enforces single-use authorization code under 50 simultaneous parallel requests", func() {
		km, err := RSAKeyManager{}.New(2048, "concurrency-key")
		Expect(err).NotTo(HaveOccurred())

		settings := AuthorizationServerSettings{}.NewDefault("https://auth.beamfoundry.com")
		encoder := DefaultJwtEncoder{}.New(km)
		generator := JwtOAuth2TokenGenerator{}.New(encoder, settings.Issuer)

		client := &RegisteredClient{
			ID:           "race-client-id",
			ClientID:     "concurrent-app",
			ClientSecret: "client-secret-xyz",
			AuthorizationGrantTypes: []AuthorizationGrantType{
				GrantTypeAuthorizationCode,
			},
			RedirectURIs:          []string{"https://app.example.com/callback"},
			RequireProofKey:       true,
			AccessTokenTimeToLive: 15 * time.Minute,
		}

		clientRepo := InMemoryRegisteredClientRepository{}.New(client)
		authService := InMemoryOAuth2AuthorizationService{}.New()
		contextHolder := &mockSecurityContextHolder{}

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

		// Setup PKCE
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		hash := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(hash[:])

		// Save authorization code in authService
		authCodeVal := "single-use-race-code-12345"
		now := time.Now()
		auth := &OAuth2Authorization{
			ID:                 "race-auth-id",
			RegisteredClientID: client.ID,
			PrincipalName:      "alice",
			AuthorizationCode: &AuthorizationCode{
				Value:               authCodeVal,
				IssuedAt:            now,
				ExpiresAt:           now.Add(5 * time.Minute),
				CodeChallenge:       challenge,
				CodeChallengeMethod: "S256",
				RedirectURI:         "https://app.example.com/callback",
				Invalidated:         false,
			},
		}
		Expect(authService.Save(auth)).NotTo(HaveOccurred())

		tokenURI, parseErr := url.Parse("https://auth.beamfoundry.com/oauth2/token")
		Expect(parseErr).NotTo(HaveOccurred())

		const concurrentRequests = 50
		var wg sync.WaitGroup
		startGate := make(chan struct{})

		var successCount int64
		var failCount int64

		wg.Add(concurrentRequests)
		for range concurrentRequests {
			go func() {
				defer wg.Done()
				<-startGate // Synchronized parallel blast

				h := NewMockSecurityHandler(HttpMethods.POST, tokenURI)
				h.SetFormValue("client_id", "concurrent-app")
				h.SetFormValue("client_secret", "client-secret-xyz")
				h.SetFormValue("grant_type", "authorization_code")
				h.SetFormValue("code", authCodeVal)
				h.SetFormValue("redirect_uri", "https://app.example.com/callback")
				h.SetFormValue("code_verifier", verifier)

				execErr := router.Execute(h)
				if execErr == nil && h.Res.Code == 200 {
					atomic.AddInt64(&successCount, 1)
				} else {
					atomic.AddInt64(&failCount, 1)
				}
			}()
		}

		close(startGate) // Release all 50 goroutines at the exact same instant
		wg.Wait()

		// Exactly one request MUST succeed
		Expect(atomic.LoadInt64(&successCount)).To(Equal(int64(1)), "Only ONE token exchange must succeed for a single-use code")
		// All other 49 requests MUST fail
		Expect(atomic.LoadInt64(&failCount)).To(Equal(int64(49)), "All subsequent parallel replay requests must be rejected")
	})
})
