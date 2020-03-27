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

var (
	ErrClientAlreadyExists    = errors.New("a client with that ID already exists")
	ErrClientNotFound         = errors.New("client not found")
	ErrClientRequestMissingID = errors.New("request must have the ID set")
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
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrConflict,
		Field: "/client/id",
	}) {
		return APIClient{}, ErrClientAlreadyExists
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return APIClient{}, ErrUnexpectedError
	}
	// TODO: more robust client returning
	return resp.Clients[0], nil
}

func (c ClientsService) Get(ctx context.Context, id string) (APIClient, error) {
	if id == "" {
		return APIClient{}, ErrClientRequestMissingID
	}
	req, err := c.client.NewRequest(ctx, http.MethodGet, c.buildURL("/"+id), nil)
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
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Param: "id",
	}) {
		return APIClient{}, ErrClientRequestMissingID
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrNotFound,
		Param: "id",
	}) {
		return APIClient{}, ErrClientNotFound
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return APIClient{}, ErrUnexpectedError
	}
	// TODO: more robust client returning
	return resp.Clients[0], nil
}

func (c ClientsService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return ErrClientRequestMissingID
	}
	req, err := c.client.NewRequest(ctx, http.MethodDelete, c.buildURL("/"+id), nil)
	if err != nil {
		return fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = c.client.MakeClientsHMACRequest(req)
	if err != nil {
		return err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	resp, err := responseFromBody(res)
	if err != nil {
		return err
	}

	// standard checks
	if resp.Errors.Contains(serverError) {
		return ErrServerError
	}
	if resp.Errors.Contains(invalidFormatError) {
		return ErrInvalidFormatError
	}
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return ErrUnauthorized
	}

	// req specific checks
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Param: "id",
	}) {
		return ErrClientRequestMissingID
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrNotFound,
		Param: "id",
	}) {
		return ErrClientNotFound
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return ErrUnexpectedError
	}
	return nil
}

func (c ClientsService) ResetSecret(ctx context.Context, id string) (APIClient, error) {
	if id == "" {
		return APIClient{}, ErrClientRequestMissingID
	}
	req, err := c.client.NewRequest(ctx, http.MethodPost, c.buildURL("/"+id+"/secret"), nil)
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
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Param: "id",
	}) {
		return APIClient{}, ErrClientRequestMissingID
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrNotFound,
		Param: "id",
	}) {
		return APIClient{}, ErrClientNotFound
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return APIClient{}, ErrUnexpectedError
	}
	// TODO: more robust client returning
	return resp.Clients[0], nil
}

func (c ClientsService) ListRedirectURIs(ctx context.Context, id string) ([]RedirectURI, error) {
	if id == "" {
		return nil, ErrClientRequestMissingID
	}
	req, err := c.client.NewRequest(ctx, http.MethodGet, c.buildURL("/"+id+"/redirectURIs"), nil)
	if err != nil {
		return nil, fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = c.client.MakeClientsHMACRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	resp, err := responseFromBody(res)
	if err != nil {
		return nil, err
	}

	// standard checks
	if resp.Errors.Contains(serverError) {
		return nil, ErrServerError
	}
	if resp.Errors.Contains(invalidFormatError) {
		return nil, ErrInvalidFormatError
	}
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return nil, ErrUnauthorized
	}

	// req specific checks
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Param: "id",
	}) {
		return nil, ErrClientRequestMissingID
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrNotFound,
		Param: "id",
	}) {
		return nil, ErrClientNotFound
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return nil, ErrUnexpectedError
	}
	return resp.RedirectURIs, nil
}

func (c ClientsService) CreateRedirectURIs(ctx context.Context, id string, uris []RedirectURI) ([]RedirectURI, error) {
	if id == "" {
		return nil, ErrClientRequestMissingID
	}
	type request struct {
		RedirectURIs []RedirectURI `json:"redirectURIs"`
	}
	b, err := json.Marshal(request{uris})
	if err != nil {
		return nil, fmt.Errorf("error serialising redirect URIs: %w", err)
	}
	buf := bytes.NewBuffer(b)
	req, err := c.client.NewRequest(ctx, http.MethodPost, c.buildURL("/"), buf)
	if err != nil {
		return nil, fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = c.client.MakeClientsHMACRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	resp, err := responseFromBody(res)
	if err != nil {
		return nil, err
	}

	// standard checks
	if resp.Errors.Contains(serverError) {
		return nil, ErrServerError
	}
	if resp.Errors.Contains(invalidFormatError) {
		return nil, ErrInvalidFormatError
	}
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return nil, ErrUnauthorized
	}

	// req specific checks
	// TODO: check for requestErrMissing on /redirectURIs/{pos}/URI
	// TODO: check for requestErrConflict on /redirectURIs/{pos}/id

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return nil, ErrUnexpectedError
	}
	return resp.RedirectURIs, nil
}

func (c ClientsService) DeleteRedirectURI(ctx context.Context, clientID, uriID string) error {
	if clientID == "" {
		return ErrClientRequestMissingID
	}
	// TODO: delete a redirect URI from a client
	return errors.New("not implemented yet")
}
