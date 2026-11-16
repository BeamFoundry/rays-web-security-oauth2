package server

import (
	"slices"
	"sync"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// RegisteredClient represents a client registered with the Authorization Server
type RegisteredClient struct {
	ID                          string                       `json:"id"`
	ClientID                    string                       `json:"client_id"`
	ClientSecret                string                       `json:"client_secret,omitempty"`
	ClientName                  string                       `json:"client_name"`
	ClientAuthenticationMethods []ClientAuthenticationMethod `json:"client_authentication_methods"`
	AuthorizationGrantTypes     []AuthorizationGrantType     `json:"authorization_grant_types"`
	RedirectURIs                []string                     `json:"redirect_uris"`
	Scopes                      []string                     `json:"scopes"`
	RequireProofKey             bool                         `json:"require_proof_key"` // Enforce PKCE
	AccessTokenTimeToLive       time.Duration                `json:"access_token_ttl"`
	RefreshTokenTimeToLive      time.Duration                `json:"refresh_token_ttl"`
}

// RegisteredClientBuilder provides a fluent builder for RegisteredClient.
type RegisteredClientBuilder struct {
	client RegisteredClient
}

// New initializes a new RegisteredClientBuilder with the specified internal ID and initialized empty slices.
func (this RegisteredClientBuilder) New(id string) *RegisteredClientBuilder {
	this.client = RegisteredClient{
		ID:                          id,
		ClientAuthenticationMethods: make([]ClientAuthenticationMethod, 0),
		AuthorizationGrantTypes:     make([]AuthorizationGrantType, 0),
		RedirectURIs:                make([]string, 0),
		Scopes:                      make([]string, 0),
	}
	return &this
}

// NewRegisteredClient creates a new RegisteredClientBuilder for the specified internal ID.
func NewRegisteredClient(id string) *RegisteredClientBuilder {
	return RegisteredClientBuilder{}.New(id)
}

// ClientID sets the OAuth 2.0 client identifier.
func (this *RegisteredClientBuilder) ClientID(clientID string) *RegisteredClientBuilder {
	this.client.ClientID = clientID
	return this
}

// ClientSecret sets the OAuth 2.0 client secret.
func (this *RegisteredClientBuilder) ClientSecret(secret string) *RegisteredClientBuilder {
	this.client.ClientSecret = secret
	return this
}

// ClientName sets the human-readable display name of the client.
func (this *RegisteredClientBuilder) ClientName(name string) *RegisteredClientBuilder {
	this.client.ClientName = name
	return this
}

// ClientAuthenticationMethod appends one or more client authentication methods.
func (this *RegisteredClientBuilder) ClientAuthenticationMethod(methods ...ClientAuthenticationMethod) *RegisteredClientBuilder {
	this.client.ClientAuthenticationMethods = append(this.client.ClientAuthenticationMethods, methods...)
	return this
}

// AuthorizationGrantType appends one or more OAuth 2.0 authorization grant types.
func (this *RegisteredClientBuilder) AuthorizationGrantType(grantTypes ...AuthorizationGrantType) *RegisteredClientBuilder {
	this.client.AuthorizationGrantTypes = append(this.client.AuthorizationGrantTypes, grantTypes...)
	return this
}

// RedirectURI appends one or more registered redirection URIs.
func (this *RegisteredClientBuilder) RedirectURI(uris ...string) *RegisteredClientBuilder {
	this.client.RedirectURIs = append(this.client.RedirectURIs, uris...)
	return this
}

// Scope appends one or more authorized scopes to the registered client.
func (this *RegisteredClientBuilder) Scope(scopes ...string) *RegisteredClientBuilder {
	this.client.Scopes = append(this.client.Scopes, scopes...)
	return this
}

// RequireProofKey configures whether PKCE (Proof Key for Code Exchange) is required for this client.
func (this *RegisteredClientBuilder) RequireProofKey(require bool) *RegisteredClientBuilder {
	this.client.RequireProofKey = require
	return this
}

// AccessTokenTimeToLive sets the lifetime duration for issued access tokens.
func (this *RegisteredClientBuilder) AccessTokenTimeToLive(ttl time.Duration) *RegisteredClientBuilder {
	this.client.AccessTokenTimeToLive = ttl
	return this
}

// RefreshTokenTimeToLive sets the lifetime duration for issued refresh tokens.
func (this *RegisteredClientBuilder) RefreshTokenTimeToLive(ttl time.Duration) *RegisteredClientBuilder {
	this.client.RefreshTokenTimeToLive = ttl
	return this
}

// Build constructs and returns the configured RegisteredClient instance.
func (this *RegisteredClientBuilder) Build() *RegisteredClient {
	res := this.client
	res.ClientAuthenticationMethods = slices.Clone(this.client.ClientAuthenticationMethods)
	res.AuthorizationGrantTypes = slices.Clone(this.client.AuthorizationGrantTypes)
	res.RedirectURIs = slices.Clone(this.client.RedirectURIs)
	res.Scopes = slices.Clone(this.client.Scopes)
	return &res
}

// RegisteredClientRepository is the registry of registered clients
type RegisteredClientRepository interface {
	// FindByID retrieves a RegisteredClient by its internal registration identifier.
	FindByID(id string) (*RegisteredClient, Error)
	// FindByClientID retrieves a RegisteredClient by its OAuth 2.0 client_id.
	FindByClientID(clientID string) (*RegisteredClient, Error)
	// Save persists or updates a RegisteredClient in the repository.
	Save(client *RegisteredClient) Error
}

// InMemoryRegisteredClientRepository stores registered clients in memory.
// Repository operations are synchronized, but callers must synchronize concurrent access to or mutation of client objects shared with the repository.
type InMemoryRegisteredClientRepository struct {
	mu         *sync.RWMutex
	byID       map[string]*RegisteredClient
	byClientID map[string]*RegisteredClient
}

// New creates a new InMemoryRegisteredClientRepository populated with the given clients.
// Repository operations are synchronized, but callers must synchronize concurrent access to or mutation of client objects shared with the repository.
func (this InMemoryRegisteredClientRepository) New(clients ...*RegisteredClient) *InMemoryRegisteredClientRepository {
	this.mu = &sync.RWMutex{}
	this.byID = make(map[string]*RegisteredClient)
	this.byClientID = make(map[string]*RegisteredClient)
	repo := &this
	for _, c := range clients {
		Try(func() {
			RaiseNilErr(repo.Save(c))
		}).LogError()
	}
	return repo
}

// NewInMemoryRegisteredClientRepository creates a new InMemoryRegisteredClientRepository populated with the given clients.
// Repository operations are synchronized, but callers must synchronize concurrent access to or mutation of client objects shared with the repository.
func NewInMemoryRegisteredClientRepository(clients ...*RegisteredClient) *InMemoryRegisteredClientRepository {
	return InMemoryRegisteredClientRepository{}.New(clients...)
}

// FindByID retrieves a RegisteredClient by its internal ID from memory.
func (this *InMemoryRegisteredClientRepository) FindByID(id string) (*RegisteredClient, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	client, ok := this.byID[id]
	if !ok {
		return nil, NewError("ClientNotFound", "client not found by id: "+id)
	}
	return client, nil
}

// FindByClientID retrieves a RegisteredClient by its OAuth 2.0 client_id from memory.
func (this *InMemoryRegisteredClientRepository) FindByClientID(clientID string) (*RegisteredClient, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	client, ok := this.byClientID[clientID]
	if !ok {
		return nil, NewError("ClientNotFound", "client not found by client_id: "+clientID)
	}
	return client, nil
}

// Save stores or updates a RegisteredClient in memory indexed by both ID and ClientID.
func (this *InMemoryRegisteredClientRepository) Save(client *RegisteredClient) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.byID[client.ID] = client
	this.byClientID[client.ClientID] = client
	return nil
}
