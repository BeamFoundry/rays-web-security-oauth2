package server

import (
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
