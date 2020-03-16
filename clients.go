package lockbox

import (
	"context"
	"errors"
	"time"
)

const (
	clientsServiceDefaultBasePath = "/clients/v1/"
)

// APIClient is a Client from the clients service. It represents an API
// consumer that can make requests against Lockbox and the APIs it is
// authenticating for.
type APIClient struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Confidential bool      `json:"confidential"`
	CreatedAt    time.Time `json:"createdAt"`
	CreatedBy    string    `json:"createdBy"`
	CreatedByIP  string    `json:"createdByIP"`
	Secret       string    `json:"secret,omitempty"`
}

// RedirectURI is a URI that is registered to an APIClient as a URI that can be
// redirected to during the OAuth2 flow.
type RedirectURI struct {
	ID          string    `json:"ID"`
	URI         string    `json:"URI"`
	IsBaseURI   bool      `json:"isBaseURI"`
	ClientID    string    `json:"clientID"`
	CreatedAt   time.Time `json:"createdAt"`
	CreatedBy   string    `json:"createdBy"`
	CreatedByIP string    `json:"createdByIP"`
}

// ClientsService is the clients service. Set the BasePath to modify where
// requests will be sent relative to the Client's base URL. ClientsService
// should only be instantiated by calling NewClient.
type ClientsService struct {
	BasePath string
	client   *Client
}

func (c ClientsService) Create(ctx context.Context, client Client) (Client, error) {
	// TODO: create a client
	return Client{}, errors.New("not implemented yet")
}

func (c ClientsService) Get(ctx context.Context, id string) (Client, error) {
	// TODO: retrieve a client
	return Client{}, errors.New("not implemented yet")
}

func (c ClientsService) Delete(ctx context.Context, id string) error {
	// TODO: delete a client
	return errors.New("not implemented yet")
}

func (c ClientsService) ResetSecret(ctx context.Context, id string) (Client, error) {
	// TODO: reset a client's secret
	return Client{}, errors.New("not implemented yet")
}

func (c ClientsService) ListRedirectURIs(ctx context.Context, id string) ([]RedirectURI, error) {
	// TODO: list the redirect URIs for a client
	return nil, errors.New("not implemented yet")
}

func (c ClientsService) CreateRedirectURIs(ctx context.Context, id string, uris []RedirectURI) ([]RedirectURI, error) {
	// TODO: create redirect URIs for a client
	return nil, errors.New("not implemented yet")
}

func (c ClientsService) DeleteRedirectURI(ctx context.Context, clientID, uriID string) error {
	// TODO: delete a redirect URI from a client
	return errors.New("not implemented yet")
}
