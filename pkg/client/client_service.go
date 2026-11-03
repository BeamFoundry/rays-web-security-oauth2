package client

import (
	"fmt"
	"sync"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2AuthorizedClientService manages authorized clients
type OAuth2AuthorizedClientService interface {
	// LoadAuthorizedClient retrieves the OAuth2AuthorizedClient for the given client registration ID and principal name.
	LoadAuthorizedClient(registrationID, principalName string) (*OAuth2AuthorizedClient, Error)
	// SaveAuthorizedClient persists or updates an OAuth2AuthorizedClient.
	SaveAuthorizedClient(authorizedClient *OAuth2AuthorizedClient) Error
	// RemoveAuthorizedClient deletes the OAuth2AuthorizedClient associated with the given client registration ID and principal name.
	RemoveAuthorizedClient(registrationID, principalName string) Error
}

// authorizedClientKey uniquely identifies an authorized client by registration ID and principal name.
type authorizedClientKey struct {
	registrationID string
	principalName  string
}

// InMemoryOAuth2AuthorizedClientService is an in-memory implementation of OAuth2AuthorizedClientService
type InMemoryOAuth2AuthorizedClientService struct {
	mu      *sync.RWMutex
	clients map[authorizedClientKey]*OAuth2AuthorizedClient
}

// New creates a new thread-safe InMemoryOAuth2AuthorizedClientService.
func (this InMemoryOAuth2AuthorizedClientService) New() *InMemoryOAuth2AuthorizedClientService {
	this.mu = &sync.RWMutex{}
	this.clients = make(map[authorizedClientKey]*OAuth2AuthorizedClient)
	return &this
}

// NewInMemoryOAuth2AuthorizedClientService creates a new InMemoryOAuth2AuthorizedClientService.
func NewInMemoryOAuth2AuthorizedClientService() *InMemoryOAuth2AuthorizedClientService {
	return InMemoryOAuth2AuthorizedClientService{}.New()
}

// key constructs the composite lookup key for a client registration ID and principal name.
func (this *InMemoryOAuth2AuthorizedClientService) key(regID, principal string) authorizedClientKey {
	return authorizedClientKey{
		registrationID: regID,
		principalName:  principal,
	}
}

// LoadAuthorizedClient looks up an OAuth2AuthorizedClient in memory by registration ID and principal name.
func (this *InMemoryOAuth2AuthorizedClientService) LoadAuthorizedClient(registrationID, principalName string) (*OAuth2AuthorizedClient, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	client, ok := this.clients[this.key(registrationID, principalName)]
	if !ok {
		return nil, NewError("AuthorizedClientNotFound", fmt.Sprintf("authorized client not found for reg=%s principal=%s", registrationID, principalName))
	}
	return client, nil
}

// SaveAuthorizedClient stores an OAuth2AuthorizedClient in memory.
func (this *InMemoryOAuth2AuthorizedClientService) SaveAuthorizedClient(client *OAuth2AuthorizedClient) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.clients[this.key(client.ClientRegistration.RegistrationID, client.PrincipalName)] = client
	return nil
}

// RemoveAuthorizedClient removes the OAuth2AuthorizedClient for the given registration ID and principal name from memory.
func (this *InMemoryOAuth2AuthorizedClientService) RemoveAuthorizedClient(registrationID, principalName string) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

	delete(this.clients, this.key(registrationID, principalName))
	return nil
}
