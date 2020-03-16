package lockbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"time"

	"yall.in"
)

const (
	clientsServiceDefaultBasePath = "/clients/v1/"
)

// APIClient is a Client from the clients service. It represents an API
// consumer that can make requests against Lockbox and the APIs it is
// authenticating for.
type APIClient struct {
	ID           string    `json:"id,omitempty"`
	Name         string    `json:"name,omitempty"`
	Confidential bool      `json:"confidential"`
	CreatedAt    time.Time `json:"createdAt,omitempty"`
	CreatedBy    string    `json:"createdBy,omitempty"`
	CreatedByIP  string    `json:"createdByIP,omitempty"`
	Secret       string    `json:"secret,omitempty,omitempty"`
}

// RedirectURI is a URI that is registered to an APIClient as a URI that can be
// redirected to during the OAuth2 flow.
type RedirectURI struct {
	ID          string    `json:"ID,omitempty"`
	URI         string    `json:"URI,omitempty"`
	IsBaseURI   bool      `json:"isBaseURI"`
	ClientID    string    `json:"clientID,omitempty"`
	CreatedAt   time.Time `json:"createdAt,omitempty"`
	CreatedBy   string    `json:"createdBy,omitempty"`
	CreatedByIP string    `json:"createdByIP,omitempty"`
}

// ClientsService is the clients service. Set the BasePath to modify where
// requests will be sent relative to the Client's base URL. ClientsService
// should only be instantiated by calling NewClient.
type ClientsService struct {
	BasePath string
	client   *Client
}

func (c ClientsService) buildURL(p string) string {
	return path.Join(c.BasePath, p)
}

func (c ClientsService) Create(ctx context.Context, client APIClient) (APIClient, error) {
	type request struct {
		Client APIClient `json:"client"`
	}
	b, err := json.Marshal(request{client})
	if err != nil {
		return APIClient{}, fmt.Errorf("error serialising client: %w", err)
	}
	buf := bytes.NewBuffer(b)
	req, err := c.client.NewRequest(ctx, http.MethodPost, c.buildURL("/"), buf)
	if err != nil {
		return APIClient{}, fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = c.client.MakeClientsHMACRequest(req)
	if err != nil {
		return APIClient{}, err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return APIClient{}, fmt.Errorf("error making request: %w", err)
	}
	resp, err := responseFromBody(res)
	if err != nil {
		return APIClient{}, err
	}

	// standard checks
	if resp.Errors.Contains(serverError) {
		return APIClient{}, ErrServerError
	}
	if resp.Errors.Contains(invalidFormatError) {
		return APIClient{}, ErrInvalidFormatError
	}
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return APIClient{}, ErrUnauthorized
	}

	// req specific checks
	// TODO: check for requestErrConflict Field "/client/id"

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return APIClient{}, ErrUnexpectedError
	}
	// TODO: more robust account returning
	return resp.Clients[0], nil
}

func (c ClientsService) Get(ctx context.Context, id string) (APIClient, error) {
	// TODO: retrieve a client
	return APIClient{}, errors.New("not implemented yet")
}

func (c ClientsService) Delete(ctx context.Context, id string) error {
	// TODO: delete a client
	return errors.New("not implemented yet")
}

func (c ClientsService) ResetSecret(ctx context.Context, id string) (APIClient, error) {
	// TODO: reset a client's secret
	return APIClient{}, errors.New("not implemented yet")
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
