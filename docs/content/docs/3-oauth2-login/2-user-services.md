---
title: "User Services & Authorities"
weight: 2
---

# User Services & Authorities

Once the authorization code has been exchanged for an access token, `rays-web-security-oauth2` delegates user profile retrieval and authority mapping to `OAuth2UserService` or `OidcUserService`.

---

## 👤 `OAuth2User` and `OidcUser`

When authentication completes successfully, an implementation of `OAuth2User` (or `OidcUser` for OpenID Connect) is stored inside the `Authentication.GetPrincipal()` object:

```go
type OAuth2User interface {
    GetName() string
    GetAttributes() map[string]any
    GetAuthorities() []GrantedAuthority
}

type OidcUser interface {
    OAuth2User
    GetIdToken() *OidcIdToken
    GetUserInfo() *OidcUserInfo
}
```

---

## ⚙️ Standard User Services

*   **`DefaultOAuth2UserService`**: Queries the provider's `UserInfoURI` with `Authorization: Bearer <token>`, parses the JSON payload, and maps scopes to authorities (`SCOPE_<name>`).
*   **`DefaultOidcUserService`**: Decodes and verifies the `id_token` claims (subject, email, profile) and merges them with optional UserInfo endpoint claims.

### Customizing User Mapping

You can supply your own `OAuth2UserService` to assign application-specific roles:

```go
type CustomOAuth2UserService struct {
    defaultService *DefaultOAuth2UserService
}

func (this *CustomOAuth2UserService) LoadUser(req *OAuth2UserRequest) (OAuth2User, Error) {
    user, err := this.defaultService.LoadUser(req)
    if err != nil {
        return nil, err
    }

    authorities := user.GetAuthorities()
    
    // Check if user is an admin in our database
    if email, ok := user.GetAttributes()["email"].(string); ok && email == "admin@example.com" {
        authorities = append(authorities, Authority("ROLE_ADMIN"))
    } else {
        authorities = append(authorities, Authority("ROLE_USER"))
    }

    return DefaultOAuth2User{}.New(authorities, user.GetAttributes(), "email"), nil
}
```

---

## 🔌 Registering the `AuthenticationProvider`

`rays-web-security`'s `AuthenticationManager` automatically detects all beans implementing `AuthenticationProvider`. Register `OAuth2LoginAuthenticationProvider` as a Beam in your configuration:

```go
func (this *WebSecurityConfig) OAuth2LoginAuthenticationProvider(
    that struct {
        userService OAuth2UserService `@:"Inject"`
    },
) AuthenticationProvider {
    return OAuth2LoginAuthenticationProvider{}.New(nil, that.userService, nil)
}
```

When `OAuth2LoginAuthenticationFilter` calls `authenticationManager.Authenticate(loginToken)`, the `AuthenticationManager` matches `Supports(loginToken)` and invokes this provider.
