---
title: "Login Filter & Endpoints"
weight: 3
---

# Login Filter & Technical Endpoints

`OAuth2LoginAuthenticationFilter` is the workhorse of the OAuth2 Login system. It implements both `SecurityFilter` and `SecurityEndpointRegistration` from `rays-web-security`.

---

## 🎯 Technical Endpoints

When the filter is initialized, it registers the following routes on the application router:

1. **Authorization Redirection:**
   `GET /oauth2/authorization/{registrationId}`
   - Resolves the matching `ClientRegistration`.
   - Generates a random `state` and PKCE `code_verifier` (with SHA-256 `code_challenge`).
   - Persists the pending `OAuth2AuthorizationRequest` in the user's HTTP session via `AuthorizationRequestRepository`.
   - Redirects the browser to the remote Identity Provider.

2. **Authorization Callback Processing:**
   `GET /login/oauth2/code/{registrationId}`
   - Extracts the `code` and `state` parameters from the query string.
   - Verifies the state matches the stored session to prevent CSRF attacks.
   - Constructs an unauthenticated `OAuth2LoginAuthenticationToken`.
   - Delegates to `AuthenticationManager.Authenticate()`.
   - Upon success:
     - Refreshes the session ID (protecting against session fixation).
     - Stores the authenticated `OAuth2AuthenticationToken` in session and `SecurityContextHolder`.
     - Redirects the user back to their originally requested URL (or default success URL).

---

## 🛡️ Session Awareness

Because OAuth2 Login requires maintaining state and user sessions, `OAuth2LoginAuthenticationFilter` embeds the `SessionAwareFilter` marker interface:

```go
type OAuth2LoginAuthenticationFilter struct {
    SessionAwareFilter
    // ...
}
```

This guarantees that if your application uses `SessionCreationPolicy().IfRequired()`, the framework will provision a session specifically for OAuth2 Login.
