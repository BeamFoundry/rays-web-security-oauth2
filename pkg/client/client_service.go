package client

import (
	"fmt"
	"sync"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2AuthorizedClientService manages authorized clients
type OAuth2AuthorizedClientService interface {
	LoadAuthorizedClient(registrationID, principalName string) (*OAuth2AuthorizedClient, Error)
	SaveAuthorizedClient(authorizedClient *OAuth2AuthorizedClient) Error
	RemoveAuthorizedClient(registrationID, principalName string) Error
}

// InMemoryOAuth2AuthorizedClientService is an in-memory implementation of OAuth2AuthorizedClientService
type InMemoryOAuth2AuthorizedClientService struct {
	mu      *sync.RWMutex
	clients map[string]*OAuth2AuthorizedClient
}

func (this InMemoryOAuth2AuthorizedClientService) New() *InMemoryOAuth2AuthorizedClientService {
	this.mu = &sync.RWMutex{}
	this.clients = make(map[string]*OAuth2AuthorizedClient)
	return &this
}

func NewInMemoryOAuth2AuthorizedClientService() *InMemoryOAuth2AuthorizedClientService {
	return InMemoryOAuth2AuthorizedClientService{}.New()
}

func (this *InMemoryOAuth2AuthorizedClientService) key(regID, principal string) string {
	return regID + "::" + principal
}

func (this *InMemoryOAuth2AuthorizedClientService) LoadAuthorizedClient(registrationID, principalName string) (*OAuth2AuthorizedClient, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	client, ok := this.clients[this.key(registrationID, principalName)]
	if !ok {
		return nil, NewError("AuthorizedClientNotFound", fmt.Sprintf("authorized client not found for reg=%s principal=%s", registrationID, principalName))
	}
	return client, nil
}

func (this *InMemoryOAuth2AuthorizedClientService) SaveAuthorizedClient(client *OAuth2AuthorizedClient) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.clients[this.key(client.ClientRegistration.RegistrationID, client.PrincipalName)] = client
	return nil
}

func (this *InMemoryOAuth2AuthorizedClientService) RemoveAuthorizedClient(registrationID, principalName string) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

	delete(this.clients, this.key(registrationID, principalName))
	return nil
}
