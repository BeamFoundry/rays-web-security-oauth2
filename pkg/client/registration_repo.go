package client

import (
	"sync"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// ClientRegistrationRepository is the registry of OAuth2 ClientRegistrations
type ClientRegistrationRepository interface {
	FindByRegistrationID(registrationID string) (*ClientRegistration, Error)
}

// InMemoryClientRegistrationRepository stores client registrations in memory
type InMemoryClientRegistrationRepository struct {
	mu            *sync.RWMutex
	registrations map[string]*ClientRegistration
}

func (this InMemoryClientRegistrationRepository) New(registrations ...*ClientRegistration) *InMemoryClientRegistrationRepository {
	this.mu = &sync.RWMutex{}
	m := make(map[string]*ClientRegistration)
	for _, reg := range registrations {
		if reg != nil {
			m[reg.RegistrationID] = reg
		}
	}
	this.registrations = m
	return &this
}

func NewInMemoryClientRegistrationRepository(registrations ...*ClientRegistration) *InMemoryClientRegistrationRepository {
	return InMemoryClientRegistrationRepository{}.New(registrations...)
}

func (this *InMemoryClientRegistrationRepository) FindByRegistrationID(id string) (*ClientRegistration, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	reg, ok := this.registrations[id]
	if !ok {
		return nil, NewError("ClientRegistrationNotFound", "client registration not found: "+id)
	}
	return reg, nil
}

func (this *InMemoryClientRegistrationRepository) Add(reg *ClientRegistration) {
	this.mu.Lock()
	defer this.mu.Unlock()
	this.registrations[reg.RegistrationID] = reg
}
