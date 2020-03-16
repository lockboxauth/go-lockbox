package lockbox

import (
	"context"
	"errors"
)

const (
	scopesServiceDefaultBasePath = "/scopes/v1/"
)

// Scope is a permission from the scopes service. It can be attached to a
// session to authorize access to resources.
type Scope struct {
	ID               string   `json:"id,omitempty"`
	UserPolicy       string   `json:"userPolicy,omitempty"`
	UserExceptions   []string `json:"userExceptions,omitempty"`
	ClientPolicy     string   `json:"clientPolicy,omitempty"`
	ClientExceptions []string `json:"clientExceptions,omitempty"`
	IsDefault        bool     `json:"isDefault"`
}

type ScopeChange struct {
	UserPolicy       *string   `json:"userPolicy,omitempty"`
	UserExceptions   *[]string `json:"userExceptions,omitempty"`
	ClientPolicy     *string   `json:"clientPolicy,omitempty"`
	ClientExceptions *[]string `json:"clientExceptions,omitempty"`
	IsDefault        *bool     `json:"isDefault,omitempty"`
}

// ScopesService is the scopes service. Set the BasePath to modify where
// requests will be sent relative to the Client's base URL. ScopesService
// should only be instantiated by calling NewClient.
type ScopesService struct {
	BasePath string
	client   *Client
}

func (s ScopesService) Create(ctx context.Context, scope Scope) (Scope, error) {
	// TODO: implement creating a scope
	return Scope{}, errors.New("not implemented yet")
}

func (s ScopesService) Update(ctx context.Context, id string, change ScopeChange) (Scope, error) {
	// TODO: implement updating a scope
	return Scope{}, errors.New("not implemented yet")
}

func (s ScopesService) Get(ctx context.Context, id string) (Scope, error) {
	// TODO: implement retrieving a scope
	return Scope{}, errors.New("not implemented yet")
}

func (s ScopesService) Delete(ctx context.Context, id string) error {
	// TODO: implement deleting a scope
	return errors.New("not implemented yet")
}

func (s ScopesService) ListDefault(ctx context.Context) ([]Scope, error) {
	// TODO: implement listing the default scopes
	return nil, errors.New("not implemented yet")
}

func (s ScopesService) GetByIDs(ctx context.Context, ids []string) (map[string]Scope, error) {
	// TODO: implement retrieving scopes by ID
	return nil, errors.New("not implemented yet")
}
