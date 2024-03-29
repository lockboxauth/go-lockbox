package lockbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"yall.in"
)

const (
	accountsServiceDefaultBasePath = "/accounts/v1/"
)

var (
	// ErrAccountRequestMissingID is returned when a request requires an
	// ID, but none was set.
	ErrAccountRequestMissingID = errors.New("request must have the ID set")

	// ErrAccountRequestMissingProfileID is returned when a request
	// requires a profile ID, but none was set.
	ErrAccountRequestMissingProfileID = errors.New("request must have the ProfileID set")

	// ErrAccountAlreadyRegistered is returned when the account that is
	// being registered has already been registered.
	ErrAccountAlreadyRegistered = errors.New("that account has already been registered")

	// ErrAccountNotFound is returned when the requested account can't be
	// found.
	ErrAccountNotFound = errors.New("account not found")

	// ErrAccountAccessDenied is returned when the authenticating
	// credentials don't have access to the requested account.
	ErrAccountAccessDenied = errors.New("account access denied")

	// ErrProfileAccessDenied is returned when the authenticating
	// credentials don't have access to the requested profile.
	ErrProfileAccessDenied = errors.New("profile access denied")
)

// Account is an Account from the accounts service. It represents a login
// method available to a user.
type Account struct {
	ID             string    `json:"id,omitempty"`
	ProfileID      string    `json:"profileID,omitempty"`
	IsRegistration bool      `json:"isRegistration"`
	CreatedAt      time.Time `json:"createdAt,omitempty"`
	LastSeenAt     time.Time `json:"lastSeenAt,omitempty"`
	LastUsedAt     time.Time `json:"lastUsedAt,omitempty"`
}

// AccountsService is the accounts service. Set the BasePath to modify where
// requests will be sent relative to the Client's base URL. AccountsService
// should only be instantiated by calling NewClient.
type AccountsService struct {
	BasePath string
	client   *Client
}

func (a AccountsService) buildURL(p string) string {
	return path.Join(a.BasePath, p)
}

// Create registers a new Account in the accounts service. If ProfileID is
// empty, IsRegistration must be true. If IsRegistration is false, ProfileID
// must be set. ProfileID cannot be set while IsRegistration is true. If
// ProfileID is set, the request will be authenticated with the token
// credentials configured on the Client.
func (a AccountsService) Create(ctx context.Context, account Account) (Account, error) {
	b, err := json.Marshal(account)
	if err != nil {
		return Account{}, fmt.Errorf("error serialising account: %w", err)
	}
	buf := bytes.NewBuffer(b)
	req, err := a.client.NewRequest(ctx, http.MethodPost, a.buildURL("/"), buf)
	if err != nil {
		return Account{}, fmt.Errorf("error constructing request: %w", err)
	}
	if account.ProfileID != "" {
		err = a.client.AddTokenCredentials(req)
		if err != nil {
			return Account{}, err
		}
	}
	jsonRequest(req)
	res, err := a.client.Do(req)
	if err != nil {
		return Account{}, fmt.Errorf("error making request: %w", err)
	}
	resp, err := responseFromBody(res)
	if err != nil {
		return Account{}, err
	}

	// standard checks
	if resp.Errors.Contains(serverError) {
		return Account{}, ErrServerError
	}
	if resp.Errors.Contains(invalidFormatError) {
		return Account{}, ErrInvalidFormatError
	}
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return Account{}, ErrUnauthorized
	}

	// req specific checks
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Field: "/id",
	}) {
		return Account{}, ErrAccountRequestMissingID
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Field: "/profileID",
	}) {
		return Account{}, ErrAccountRequestMissingProfileID
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrConflict,
		Field: "/id",
	}) {
		return Account{}, ErrAccountAlreadyRegistered
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return Account{}, ErrUnexpectedError
	}

	if len(resp.Accounts) < 1 {
		return Account{}, fmt.Errorf("%w: no account found", ErrUnexpectedResponse)
	}
	return resp.Accounts[0], nil
}

// Get retrieves the Account specified by `id` from the accounts service. The
// request will be authenticated with the token credentials configured on the
// Client.
func (a AccountsService) Get(ctx context.Context, id string) (Account, error) {
	if id == "" {
		return Account{}, ErrAccountRequestMissingID
	}
	req, err := a.client.NewRequest(ctx, http.MethodGet, a.buildURL(id), nil)
	if err != nil {
		return Account{}, fmt.Errorf("error constructing request: %w", err)
	}
	err = a.client.AddTokenCredentials(req)
	if err != nil {
		return Account{}, err
	}
	jsonRequest(req)
	res, err := a.client.Do(req)
	if err != nil {
		return Account{}, fmt.Errorf("error making request: %w", err)
	}
	resp, err := responseFromBody(res)
	if err != nil {
		return Account{}, err
	}

	// standard checks
	if resp.Errors.Contains(serverError) {
		return Account{}, ErrServerError
	}
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return Account{}, ErrUnauthorized
	}

	// req specific checks
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrNotFound,
		Param: "id",
	}) {
		return Account{}, ErrAccountNotFound
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrAccessDenied,
		Param: "id",
	}) {
		return Account{}, ErrAccountAccessDenied
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return Account{}, ErrUnexpectedError
	}

	if len(resp.Accounts) < 1 {
		return Account{}, fmt.Errorf("%w: no account found", ErrUnexpectedResponse)
	}
	return resp.Accounts[0], nil
}

// ListByProfileID returns a list of Accounts associated with profileID. The
// request will be authenticated with the token credentials configured on the
// Client.
func (a AccountsService) ListByProfileID(ctx context.Context, profileID string) ([]Account, error) {
	if profileID == "" {
		return nil, ErrAccountRequestMissingProfileID
	}
	v := url.Values{}
	v.Set("profileID", profileID)
	req, err := a.client.NewRequest(ctx, http.MethodGet, a.buildURL("?"+v.Encode()), nil)
	if err != nil {
		return nil, fmt.Errorf("error constructing request: %w", err)
	}
	err = a.client.AddTokenCredentials(req)
	if err != nil {
		return nil, err
	}
	jsonRequest(req)
	res, err := a.client.Do(req)
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
		Slug:  requestErrMissing,
		Param: "profileID",
	}) {
		return nil, ErrAccountRequestMissingProfileID
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrAccessDenied,
		Param: "profileID",
	}) {
		return nil, ErrProfileAccessDenied
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return nil, ErrUnexpectedError
	}

	return resp.Accounts, nil
}

// Delete removes an Account from the accounts service. The request will be
// authenticated with the token credentials configured on the Client.
func (a AccountsService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return ErrAccountRequestMissingID
	}
	req, err := a.client.NewRequest(ctx, http.MethodDelete, a.buildURL(id), nil)
	if err != nil {
		return fmt.Errorf("error constructing request: %w", err)
	}
	err = a.client.AddTokenCredentials(req)
	if err != nil {
		return err
	}
	jsonRequest(req)
	res, err := a.client.Do(req)
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
		return ErrAccountNotFound
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrAccessDenied,
		Param: "id",
	}) {
		return ErrAccountAccessDenied
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return ErrUnexpectedError
	}

	return nil
}
