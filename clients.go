package lockbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"time"

	"yall.in"
)

const (
	clientsServiceDefaultBasePath = "/clients/v1/"
)

var (
	// ErrClientAlreadyExists is returned when the client being created
	// already exists.
	ErrClientAlreadyExists = errors.New("a client with that ID already exists")

	// ErrClientNotFound is returned when the client being requested can't
	// be found.
	ErrClientNotFound = errors.New("client not found")

	// ErrClientRedirectURINotFound is returned when the redirect URI being
	// requested can't be found.
	ErrClientRedirectURINotFound = errors.New("redirect URI not found")

	// ErrClientRequestMissingID is returned when a client request requires
	// an ID to be set, but no ID is set.
	ErrClientRequestMissingID = errors.New("request must have the ID set")

	// ErrClientRequestMissingRedirectURIID is returned when a client
	// request requires a RedirectURI ID to be set, but no RedirectURI ID
	// is set.
	ErrClientRequestMissingRedirectURIID = errors.New("request must have the URI ID set")
)

var (
	redirectURIURIIndexRegexp = regexp.MustCompile("^/redirectURIs/([0-9]*)/URI$")
	redirectURIIDIndexRegexp  = regexp.MustCompile("^/redirectURIs/([0-9]*)/id$")
)

// ErrRedirectURIURIMissing is an error type indicating the RedirectURI that
// has no URI set when a URI is required.
type ErrRedirectURIURIMissing RedirectURI

func (e ErrRedirectURIURIMissing) Error() string {
	return fmt.Sprintf("redirect URI %s must have its URI set", e.ID)
}

// ErrRedirectURIIDConflict is an error type indicating the RedirectURI that
// has an ID that already exists.
type ErrRedirectURIIDConflict RedirectURI

func (e ErrRedirectURIIDConflict) Error() string {
	return fmt.Sprintf("redirect URI %s has an ID that has already been used", e.ID)
}

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
	Secret       string    `json:"secret,omitempty"`
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

// Create registers a new APIClient in the clients service. The request will be
// authenticated with the client HMAC credentials set on the go-lockbox client.
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

	if len(resp.Clients) < 1 {
		return APIClient{}, fmt.Errorf("no client found in response; this is almost certainly a server error")
	}
	return resp.Clients[0], nil
}

// Get retrieves the APIClient specified by id from the clients service. It is
// authenticated using the client HMAC credentials on the go-lockbox client.
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
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return APIClient{}, ErrUnauthorized
	}

	// req specific checks
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

	if len(resp.Clients) < 1 {
		return APIClient{}, fmt.Errorf("no client found in response; this is almost certainly a server error")
	}
	return resp.Clients[0], nil
}

// Delete removes the client specified by id from the clients service. It is
// authenticated using the client HMAC credentials on the go-lockbox client.
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
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return ErrUnauthorized
	}

	// req specific checks
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

// ResetSecret resets the client secret in the clients service for the client
// specified by id. It authenticates using the client HMAC credentials on the
// go-lockbox client.
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
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return APIClient{}, ErrUnauthorized
	}

	// req specific checks
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

	if len(resp.Clients) < 1 {
		return APIClient{}, fmt.Errorf("no client found in response; this is almost certainly a server error")
	}
	return resp.Clients[0], nil
}

// ListRedirectURIs returns the RedirectURIs configured for the client
// specified by id in the clients service. It authenticates using the client
// HMAC credentials in the go-lockbox client.
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
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return nil, ErrUnauthorized
	}

	// req specific checks
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

// CreateRedirectURIs configures the client specified by id in the clients
// service with new RedirectURIs. It authenticates using the client HMAC
// credentials in go-lockbox.
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
	req, err := c.client.NewRequest(ctx, http.MethodPost, c.buildURL("/"+id+"/redirectURIs"), buf)
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
		Slug:  requestErrNotFound,
		Param: "id",
	}) {
		return nil, ErrClientNotFound
	}
	if matches := resp.Errors.FieldMatches(requestErrMissing, redirectURIURIIndexRegexp); matches != nil {
		if len(matches) > 0 && len(matches[0]) > 1 {
			posStr := matches[0][1]
			pos, err := strconv.Atoi(posStr)
			if err != nil {
				yall.FromContext(ctx).WithError(err).WithField("field_value", matches[0][0]).Error("error parsing which redirect URI caused an error")
			} else if len(uris) <= pos {
				yall.FromContext(ctx).WithField("field_value", matches[0][0]).Error("error parsing which redirect URI caused an error; returned error points to a redirect URI that wasn't passed")
			} else {
				return nil, ErrRedirectURIURIMissing(uris[pos])
			}
		}
	}
	if matches := resp.Errors.FieldMatches(requestErrConflict, redirectURIIDIndexRegexp); matches != nil {
		if len(matches) > 0 && len(matches[0]) > 1 {
			posStr := matches[0][1]
			pos, err := strconv.Atoi(posStr)
			if err != nil {
				yall.FromContext(ctx).WithError(err).WithField("field_value", matches[0][0]).Error("error parsing which redirect URI caused an error")
			} else if len(uris) <= pos {
				yall.FromContext(ctx).WithField("field_value", matches[0][0]).Error("error parsing which redirect URI caused an error; returned error points to a redirect URI that wasn't passed")
			} else {
				return nil, ErrRedirectURIIDConflict(uris[pos])
			}
		}
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return nil, ErrUnexpectedError
	}
	return resp.RedirectURIs, nil
}

// DeleteRedirectURI removes the RedirectURI specified by uriID from the client
// specified by clientID in the clients service. It authenticates using the
// client HMAC credentials in the go-lockbox client.
func (c ClientsService) DeleteRedirectURI(ctx context.Context, clientID, uriID string) error {
	if clientID == "" {
		return ErrClientRequestMissingID
	}
	if uriID == "" {
		return ErrClientRequestMissingRedirectURIID
	}
	req, err := c.client.NewRequest(ctx, http.MethodDelete, c.buildURL("/"+clientID+"/redirectURIs/"+uriID), nil)
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
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return ErrUnauthorized
	}

	// req specific checks
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrNotFound,
		Param: "id",
	}) {
		return ErrClientNotFound
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrNotFound,
		Param: "uri",
	}) {
		return ErrClientRedirectURINotFound
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return ErrUnexpectedError
	}
	return nil
}
