---
title: "Token Persistence & Services"
weight: 2
---

# Token Persistence & Services

The `OAuth2AuthorizedClientService` interface defines the contract for persisting authorized clients across requests:

```go
type OAuth2AuthorizedClientService interface {
    LoadAuthorizedClient(registrationID, principalName string) (*OAuth2AuthorizedClient, Error)
    SaveAuthorizedClient(authorizedClient *OAuth2AuthorizedClient) Error
    RemoveAuthorizedClient(registrationID, principalName string) Error
}
```

---

## 💾 Storage Implementations

1. **`InMemoryOAuth2AuthorizedClientService`:**
   Stores tokens in an in-memory thread-safe map. Ideal for local testing and background service workers that do not span multiple server instances.

2. **Session Storage:**
   Stores tokens directly inside the user's HTTP session via `SecurityHandler.SetSessionValue(...)`.

3. **Database Storage (Rays ORM):**
   In clustered production environments, implement `OAuth2AuthorizedClientService` using `rays-orm` to persist tokens into PostgreSQL, MySQL, or SQLite tables.
