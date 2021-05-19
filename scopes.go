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

	"yall.in"
)

const (
	scopesServiceDefaultBasePath = "/scopes/v1/"

	// ScopesPolicyDenyAll is a constant for a scopes policy that denies
	// all use of the scope, with no exceptions.
	ScopesPolicyDenyAll = "DENY_ALL"

	// ScopesPolicyDefaultDeny is a constant for a scopes policy that
	// denies all use of the scope by default, with exceptions.
	ScopesPolicyDefaultDeny = "DEFAULT_DENY"

	// ScopesPolicyAllowAll is a constant for a scopes policy that allows
	// all use of the scope, with no exceptions.
	ScopesPolicyAllowAll = "ALLOW_ALL"

	// ScopesPolicyDefaultAllow is a constant for a scopes policy that
	// allows all use of the scope by default, with exceptions.
	ScopesPolicyDefaultAllow = "DEFAULT_ALLOW"
)

var (
	// ErrScopeAlreadyExists is returned when the Scope being created
	// already exists in the scopes service.
	ErrScopeAlreadyExists = errors.New("a scope with that ID already exists")

	// ErrScopeNotFound is returned when the requested scope can't be found
	// in the scopes service.
	ErrScopeNotFound = errors.New("scope not found")

	// ErrScopeRequestMissingUserPolicy is returned when a request to the
	// scopes service requires a UserPolicy, and none is set.
	ErrScopeRequestMissingUserPolicy = errors.New("request must have the user policy set")

	// ErrScopeRequestMissingClientPolicy is returned when a request to the
	// scopes service requires a ClientPolicy, and none is set.
	ErrScopeRequestMissingClientPolicy = errors.New("request must have the client policy set")

	// ErrScopeRequestMissingID is returned when a request to the scopes
	// service requires an ID, and none is set.
	ErrScopeRequestMissingID = errors.New("request must have the ID set")

	// ErrScopeRequestInvalidUserPolicy is returned when a request to the
	// scopes service specifies an invalid user policy.
	ErrScopeRequestInvalidUserPolicy = errors.New("invalid user policy")

	// ErrScopeRequestInvalidClientPolicy is returned when a request to the
	// scopes service specifies an invalid client policy.
	ErrScopeRequestInvalidClientPolicy = errors.New("invalid client policy")
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

// ScopeChange captures a modification to a Scope.
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

func (s ScopesService) buildURL(p string) string {
	return path.Join(s.BasePath, p)
}

// Create adds the passed Scope to the scopes service. It uses the scopes HMAC
// credentials in the client.
func (s ScopesService) Create(ctx context.Context, scope Scope) (Scope, error) {
	b, err := json.Marshal(scope)
	if err != nil {
		return Scope{}, fmt.Errorf("error serialising scope: %w", err)
	}
	buf := bytes.NewBuffer(b)
	req, err := s.client.NewRequest(ctx, http.MethodPost, s.buildURL("/"), buf)
	if err != nil {
		return Scope{}, fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = s.client.MakeScopesHMACRequest(req)
	if err != nil {
		return Scope{}, err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return Scope{}, fmt.Errorf("error making request: %w", err)
	}
	resp, err := responseFromBody(res)
	if err != nil {
		return Scope{}, err
	}

	// standard checks
	if resp.Errors.Contains(serverError) {
		return Scope{}, ErrServerError
	}
	if resp.Errors.Contains(invalidFormatError) {
		return Scope{}, ErrInvalidFormatError
	}
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return Scope{}, ErrUnauthorized
	}

	// req specific checks
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Field: "/clientPolicy",
	}) {
		return Scope{}, ErrScopeRequestMissingClientPolicy
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrInvalidValue,
		Field: "/clientPolicy",
	}) {
		return Scope{}, ErrScopeRequestInvalidClientPolicy
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Field: "/userPolicy",
	}) {
		return Scope{}, ErrScopeRequestMissingUserPolicy
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrInvalidValue,
		Field: "/userPolicy",
	}) {
		return Scope{}, ErrScopeRequestInvalidUserPolicy
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Field: "/id",
	}) {
		return Scope{}, ErrScopeRequestMissingID
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrConflict,
		Field: "/id",
	}) {
		return Scope{}, ErrScopeAlreadyExists
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return Scope{}, ErrUnexpectedError
	}

	if len(resp.Scopes) < 1 {
		return Scope{}, fmt.Errorf("no scopes in the response; this is almost certainly a server error")
	}
	return resp.Scopes[0], nil
}

// Update applies the specified change to the Scope identified by the passed ID
// in the scopes service. It uses the scopes HMAC credentials in the client to
// authenticate.
func (s ScopesService) Update(ctx context.Context, id string, change ScopeChange) (Scope, error) {
	if id == "" {
		return Scope{}, ErrScopeRequestMissingID
	}
	b, err := json.Marshal(change)
	if err != nil {
		return Scope{}, fmt.Errorf("error serialising scope change: %w", err)
	}
	buf := bytes.NewBuffer(b)
	req, err := s.client.NewRequest(ctx, http.MethodPatch, s.buildURL("/"+url.PathEscape(id)), buf)
	if err != nil {
		return Scope{}, fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = s.client.MakeScopesHMACRequest(req)
	if err != nil {
		return Scope{}, err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return Scope{}, fmt.Errorf("error making request: %w", err)
	}
	resp, err := responseFromBody(res)
	if err != nil {
		return Scope{}, err
	}

	// standard checks
	if resp.Errors.Contains(serverError) {
		return Scope{}, ErrServerError
	}
	if resp.Errors.Contains(invalidFormatError) {
		return Scope{}, ErrInvalidFormatError
	}
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return Scope{}, ErrUnauthorized
	}

	// req specific checks
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrInvalidValue,
		Field: "/clientPolicy",
	}) {
		return Scope{}, ErrScopeRequestInvalidClientPolicy
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrInvalidValue,
		Field: "/userPolicy",
	}) {
		return Scope{}, ErrScopeRequestInvalidUserPolicy
	}
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrNotFound,
		Param: "id",
	}) {
		return Scope{}, ErrScopeNotFound
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return Scope{}, ErrUnexpectedError
	}

	if len(resp.Scopes) < 1 {
		return Scope{}, fmt.Errorf("no scopes in the response; this is almost certainly a server error")
	}
	return resp.Scopes[0], nil
}

// Get returns the Scope specified by ID from the scopes service. It uses the
// scopes HMAC credentials in the client to authenticate.
func (s ScopesService) Get(ctx context.Context, id string) (Scope, error) {
	if id == "" {
		return Scope{}, ErrScopeRequestMissingID
	}
	req, err := s.client.NewRequest(ctx, http.MethodGet, s.buildURL("/"+url.PathEscape(id)), nil)
	if err != nil {
		return Scope{}, fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = s.client.MakeScopesHMACRequest(req)
	if err != nil {
		return Scope{}, err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return Scope{}, fmt.Errorf("error making request: %w", err)
	}
	resp, err := responseFromBody(res)
	if err != nil {
		return Scope{}, err
	}

	// standard checks
	if resp.Errors.Contains(serverError) {
		return Scope{}, ErrServerError
	}
	if resp.Errors.Contains(RequestError{
		Slug:   requestErrAccessDenied,
		Header: "Authorization",
	}) {
		return Scope{}, ErrUnauthorized
	}

	// req specific checks
	if resp.Errors.Contains(RequestError{
		Slug:  requestErrNotFound,
		Param: "id",
	}) {
		return Scope{}, ErrScopeNotFound
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return Scope{}, ErrUnexpectedError
	}

	if len(resp.Scopes) < 1 {
		return Scope{}, fmt.Errorf("no scopes in the response; this is almost certainly a server error")
	}
	return resp.Scopes[0], nil
}

// Delete removes the Scope identified by ID from the scopes service. It uses
// the scopes HMAC credentials in the client to authenticate.
func (s ScopesService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return ErrScopeRequestMissingID
	}
	req, err := s.client.NewRequest(ctx, http.MethodDelete, s.buildURL("/"+url.PathEscape(id)), nil)
	if err != nil {
		return fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = s.client.MakeScopesHMACRequest(req)
	if err != nil {
		return err
	}
	res, err := s.client.Do(req)
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
		return ErrScopeNotFound
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return ErrUnexpectedError
	}
	return nil
}

// ListDefault returns the default set of Scopes from the scopes service. It
// uses the scopes HMAC credentials to authenticate.
func (s ScopesService) ListDefault(ctx context.Context) ([]Scope, error) {
	req, err := s.client.NewRequest(ctx, http.MethodGet, s.buildURL("/?default=true"), nil)
	if err != nil {
		return nil, fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = s.client.MakeScopesHMACRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := s.client.Do(req)
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
		Slug:  requestErrConflict,
		Param: "default,id",
	}) {
		return nil, fmt.Errorf("tried to list default scopes and specific scopes; this is a go-lockbox error, please report it")
	}

	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Param: "default",
	}) {
		return nil, fmt.Errorf("incorrectly formatted request; this is a go-lockbox error, please report it")
	}

	if resp.Errors.Contains(RequestError{
		Slug:  requestErrInvalidValue,
		Param: "default",
	}) {
		return nil, fmt.Errorf("invalid value for default param; this is a go-lockbox error, please report it")
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return nil, ErrUnexpectedError
	}
	return resp.Scopes, nil
}

// GetByIDs returns the Scopes specified by the passed IDs from the scopes
// service. It uses the scopes HMAC credentials in the client to authenticate.
// The result will be a map with a key of the scope's ID and the value being
// the Scope itself.
func (s ScopesService) GetByIDs(ctx context.Context, ids []string) (map[string]Scope, error) {
	v := url.Values{}
	v["id"] = append(v["id"], ids...)
	req, err := s.client.NewRequest(ctx, http.MethodGet, s.buildURL("/?"+v.Encode()), nil)
	if err != nil {
		return nil, fmt.Errorf("error constructing request: %w", err)
	}
	jsonRequest(req)
	err = s.client.MakeScopesHMACRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := s.client.Do(req)
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
		Slug:  requestErrConflict,
		Param: "default,id",
	}) {
		return nil, fmt.Errorf("tried to list default scopes and specific scopes; this is a go-lockbox error, please report it")
	}

	if resp.Errors.Contains(RequestError{
		Slug:  requestErrMissing,
		Param: "default",
	}) {
		return nil, fmt.Errorf("incorrectly formatted request; this is a go-lockbox error, please report it")
	}

	if resp.Errors.Contains(RequestError{
		Slug:  requestErrInvalidValue,
		Param: "default",
	}) {
		return nil, fmt.Errorf("invalid value for default param; this is a go-lockbox error, please report it")
	}

	if len(resp.Errors) > 0 {
		yall.FromContext(ctx).WithField("errors", resp.Errors).Error("unexpected error in response")
		return nil, ErrUnexpectedError
	}

	ret := make(map[string]Scope, len(resp.Scopes))
	for _, scope := range resp.Scopes {
		ret[scope.ID] = scope
	}
	return ret, nil
}
