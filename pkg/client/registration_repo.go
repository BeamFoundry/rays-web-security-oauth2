package client

import (
	"sync"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// ClientRegistrationRepository is the registry of OAuth2 ClientRegistrations
type ClientRegistrationRepository interface {
	// FindByRegistrationID retrieves a ClientRegistration by its unique registration ID.
	FindByRegistrationID(registrationID string) (*ClientRegistration, Error)
}

// InMemoryClientRegistrationRepository stores client registrations in memory.
// Repository operations are synchronized, but callers must synchronize concurrent access to or mutation of ClientRegistration objects shared with the repository.
type InMemoryClientRegistrationRepository struct {
	mu            *sync.RWMutex
	registrations map[string]*ClientRegistration
}

// New creates a new InMemoryClientRegistrationRepository populated with the given client registrations.
// Repository operations are synchronized, but callers must synchronize concurrent access to or mutation of ClientRegistration objects shared with the repository.
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

// NewInMemoryClientRegistrationRepository creates a new InMemoryClientRegistrationRepository populated with the given client registrations.
// Repository operations are synchronized, but callers must synchronize concurrent access to or mutation of ClientRegistration objects shared with the repository.
func NewInMemoryClientRegistrationRepository(registrations ...*ClientRegistration) *InMemoryClientRegistrationRepository {
	return InMemoryClientRegistrationRepository{}.New(registrations...)
}

// FindByRegistrationID looks up a ClientRegistration by its registration ID in memory.
func (this *InMemoryClientRegistrationRepository) FindByRegistrationID(id string) (*ClientRegistration, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	reg, ok := this.registrations[id]
	if !ok {
		return nil, NewError("ClientRegistrationNotFound", "client registration not found: "+id)
	}
	return reg, nil
}

// Add registers or replaces a ClientRegistration in memory.
func (this *InMemoryClientRegistrationRepository) Add(reg *ClientRegistration) {
	this.mu.Lock()
	defer this.mu.Unlock()
	this.registrations[reg.RegistrationID] = reg
}
