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
)

const (
	accountsServiceDefaultBasePath = "/accounts/v1/"
)

// Account is an Account from the accounts service. It represents a login
// method available to a user.
type Account struct {
	ID             string    `json:"id"`
	ProfileID      string    `json:"profileID"`
	IsRegistration bool      `json:"isRegistration"`
	CreatedAt      time.Time `json:"createdAt"`
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
func (a AccountsService) Create(ctx context.Context, account Account) error {
	b, err := json.Marshal(account)
	if err != nil {
		return fmt.Errorf("error serialising account: %w", err)
	}
	buf := bytes.NewBuffer(b)
	req, err := a.client.NewRequest(ctx, http.MethodPost, a.buildURL("/"), buf)
	if err != nil {
		return fmt.Errorf("error constructing request: %w", err)
	}
	if account.ProfileID != "" {
		err = a.client.AddTokenCredentials(req)
		if err != nil {
			return err
		}
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
	// TODO: check for ErrInvalidFormat, Field "/"
	// TODO: check for ErrAccessDenied, Header "Authorization"

	// req specific checks
	// TODO: check for ErrMissing, Field "/id"
	// TODO: check for ErrMissing, Field "/profileID"
	// TODO: check for ErrConflict, Field "/id"
	return nil
}

// Get retrieves the Account specified by `id` from the accounts service. The
// request will be authenticated with the token credentials configured on the
// Client.
func (a AccountsService) Get(ctx context.Context, id string) (Account, error) {
	req, err := a.client.NewRequest(ctx, http.MethodGet, a.buildURL(id), nil)
	if err != nil {
		return Account{}, fmt.Errorf("error constructing request: %w", err)
	}
	err = a.client.AddTokenCredentials(req)
	if err != nil {
		return Account{}, err
	}
	jsonRequest(req)
	_, err = a.client.Do(req)
	if err != nil {
		return Account{}, fmt.Errorf("error making request: %w", err)
	}
	// TODO: check response code, return errors, unmarshal body
	return Account{}, errors.New("not yet implemented")
}

// ListByProfileID returns a list of Accounts associated with profileID. The
// request will be authenticated with the token credentials configured on the
// Client.
func (a AccountsService) ListByProfileID(ctx context.Context, profileID string) ([]Account, error) {
	v := url.Values{}
	v.Set("profile_id", profileID)
	req, err := a.client.NewRequest(ctx, http.MethodGet, a.buildURL("?"+v.Encode()), nil)
	if err != nil {
		return nil, fmt.Errorf("error constructing request: %w", err)
	}
	err = a.client.AddTokenCredentials(req)
	if err != nil {
		return nil, err
	}
	jsonRequest(req)
	_, err = a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	// TODO: check response code, return errors, unmarshal body
	return nil, errors.New("not yet implemented")
}

// Delete removes an Account from the accounts service. The request will be
// authenticated with the token credentials configured on the Client.
func (a AccountsService) Delete(ctx context.Context, id string) error {
	req, err := a.client.NewRequest(ctx, http.MethodDelete, a.buildURL(id), nil)
	if err != nil {
		return fmt.Errorf("error constructing request: %w", err)
	}
	err = a.client.AddTokenCredentials(req)
	if err != nil {
		return err
	}
	jsonRequest(req)
	_, err = a.client.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	// TODO: check response code, return errors
	return errors.New("not yet implemented")
}
