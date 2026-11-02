---
title: "8. Testing"
weight: 8
---

# Testing OAuth2 Applications with Ginkgo

All `rays-web-security-oauth2` components are tested using the [Ginkgo v2](https://onsi.github.io/ginkgo/) BDD testing framework and [Gomega](https://onsi.github.io/gomega/) matcher library, following the standardized testing conventions of the **Rays Framework** and `rays-web-security`.

---

## 🧪 Ginkgo Test Suite Setup

Every package contains a `*_suite_test.go` file that bootstraps Ginkgo:

```go
package resourceserver_test

import (
    "testing"

    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
)

func TestResourceServer(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "OAuth2 Resource Server Suite")
}
```

---

## 🛡️ Testing Resource Server with Mock JWTs

When testing Resource Server components or APIs secured with Bearer tokens, you can issue test tokens dynamically with `RSAKeyManager` (or `JwxJwtEncoder` for multi-algorithm keys):

```go
var _ = Describe("JwtAuthenticationProvider", func() {
    It("authenticates a valid Bearer token and returns JwtAuthenticationToken", func() {
        // 1. Generate local test keypair
        km, err := RSAKeyManager{}.New(2048, "rs-test-key")
        Expect(err).NotTo(HaveOccurred())

        encoder := DefaultJwtEncoder{}.New(km)
        now := time.Now()
        claimsSet := JwtClaimsSet{}.New()
        claimsSet.Issuer = "https://auth.example.com"
        claimsSet.Subject = "alice"
        claimsSet.IssuedAt = now
        claimsSet.ExpiresAt = now.Add(30 * time.Minute)
        claimsSet.Claims["scope"] = "read write admin"

        token, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claimsSet})
        Expect(err).NotTo(HaveOccurred())

        // 2. Decode and verify via JwtAuthenticationProvider
        decoder := NimbusJwtDecoder{}.New(km).WithIssuer("https://auth.example.com")
        provider := JwtAuthenticationProvider{}.New(decoder)

        bearerToken := BearerTokenAuthenticationToken{}.New(token.TokenValue)
        Expect(provider.Supports(bearerToken)).To(BeTrue())

        auth, authEx := provider.Authenticate(bearerToken)
        Expect(authEx).NotTo(HaveOccurred())
        Expect(auth.IsAuthenticated()).To(BeTrue())
        Expect(auth.GetName()).To(Equal("alice"))

        var authNames []string
        for _, a := range auth.GetAuthorities() {
            authNames = append(authNames, a.Authority())
        }
        Expect(authNames).To(ConsistOf("SCOPE_read", "SCOPE_write", "SCOPE_admin"))
    })
})
```

---

## 🌐 Testing Security Filters with `MockSecurityHandler`

Use `MockSecurityHandler` and `MockSecurityRouter` from `github.com/BeamFoundry/rays-web-security/pkg/testing` to test HTTP filter behavior without starting a full HTTP server:

```go
var _ = Describe("BearerTokenAuthenticationFilter", func() {
    It("authenticates request and populates SecurityContext when Bearer token is present", func() {
        u, err := url.Parse("https://api.example.com/resource")
        Expect(err).NotTo(HaveOccurred())
        
        handler := NewMockSecurityHandler(HttpMethods.GET, u)
        handler.SetHeader("Authorization", "Bearer valid-token")

        chainEx := filter.Authenticate(handler)
        Expect(chainEx).NotTo(BeNil())
        Expect(chainEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))

        ctxAuth := contextHolder.GetContext().GetAuthentication()
        Expect(ctxAuth).NotTo(BeNil())
        Expect(ctxAuth.GetName()).To(Equal("bob"))
    })
})
```

---

## 🗃️ In-Memory Repositories for Testing

For testing OAuth2 Login, Client, and Authorization Server flows without requiring external databases:

*   **`InMemoryClientRegistrationRepository{}.New(...)`**: Pre-register mock OAuth2 providers (`google`, `github`, etc.).
*   **`InMemoryOAuth2AuthorizedClientService{}.New()`**: Store and inspect tokens for authorized clients.
*   **`SessionAuthorizationRequestRepository{}.New()`**: Persist and inspect PKCE state in mock sessions.
*   **`InMemoryRegisteredClientRepository{}.New(...)`**: Register OAuth2 clients for testing Authorization Server.
*   **`InMemoryOAuth2AuthorizationService{}.New()`**: Store and inspect authorization codes, access tokens, and refresh tokens.

---

## 🚀 Running the Full Test Suite

Run all test suites across the repository with Ginkgo:

```bash
# Run all suites with verbose output
go test -v ./...

# Run all suites without cache
go test -count=1 ./...
```
