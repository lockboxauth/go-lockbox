package lockbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	oauth2ServiceDefaultBasePath = "/oauth2/v1/"

	oauth2ServerError                  = "server_error"
	oauth2InvalidRequestError          = "invalid_request"
	oauth2InvalidGrantError            = "invalid_grant"
	oauth2InvalidClientError           = "invalid_client"
	oauth2UnsupportedResponseTypeError = "unsupported_response_type"
)

var (
	// ErrOAuth2RequestMissingEmail is returned when a request requires an
	// email, but none was set.
	ErrOAuth2RequestMissingEmail = errors.New("email must be set")

	// ErrOAuth2RequestMissingCode is returned when a request requires a
	// code, but none was set.
	ErrOAuth2RequestMissingCode = errors.New("code must be set")

	// ErrOAuth2RequestMissingToken is returned when a request requires a
	// token, but none is set.
	ErrOAuth2RequestMissingToken = errors.New("token must be set")

	// ErrInvalidGrantError is returned when a grant that is invalid, for
	// any reason, is used.
	ErrInvalidGrantError = errors.New("invalid grant")

	// ErrInvalidClientCredentialsError is returned when the client
	// credentials that were presented were invalid, for any reason.
	ErrInvalidClientCredentialsError = errors.New("invalid client credentials")

	// ErrUnsupportedResponseTypeError is returned when the server doesn't
	// recognize the response type that go-lockbox is requesting.
	ErrUnsupportedResponseTypeError = errors.New("unsupported response type; this is either a server or go-lockbox error")

	// ErrUnexpectedBody is returned if a response body is returned for a
	// request that doesn't expect a response.
	ErrUnexpectedBody = errors.New("unexpected body; this request shouldn't return a body, but it did, possibly an error we didn't expect or couldn't parse. This is either a server or go-lockbox error")
)

// OAuth2Service is the oauth2 service. Set the BasePath to modify where
// requests will be sent relative to the Client's base URL. OAuth2Service
// should only be instantiated by calling NewClient.
type OAuth2Service struct {
	BasePath string
	client   *Client
}

func (o OAuth2Service) buildURL(p string) string {
	return path.Join(o.BasePath, p)
}

// OAuth2Response is used to represent all the information returned in the body
// of the response to an OAuth2 request.
type OAuth2Response struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Error        string `json:"error,omitempty"`
}

// ExchangeRefreshToken uses the refresh token passed to obtain a new access
// token and refresh token from the oauth2 service.
func (o OAuth2Service) ExchangeRefreshToken(ctx context.Context, token string, scopes []string) (OAuth2Response, error) {
	if token == "" {
		return OAuth2Response{}, ErrOAuth2RequestMissingToken
	}
	vals := url.Values{}
	vals.Set("grant_type", "refresh_token")
	vals.Set("refresh_token", token)
	if len(scopes) > 0 {
		vals.Set("scope", strings.Join(scopes, " "))
	}
	buf := bytes.NewBuffer([]byte(vals.Encode()))
	req, err := o.client.NewRequest(ctx, http.MethodPost, o.buildURL("/token"), buf)
	if err != nil {
		return OAuth2Response{}, fmt.Errorf("error constructing request: %w", err)
	}
	err = o.client.AddClientCredentials(req)
	if err != nil {
		return OAuth2Response{}, err
	}
	res, err := o.client.Do(req)
	if err != nil {
		return OAuth2Response{}, fmt.Errorf("error making request: %w", err)
	}

	resp, err := oauthResponse(res)
	if err != nil {
		return OAuth2Response{}, err
	}

	if res.StatusCode == http.StatusInternalServerError &&
		resp.Error == oauth2ServerError {
		return resp, ErrServerError
	}
	if res.StatusCode == http.StatusUnauthorized &&
		resp.Error == oauth2InvalidClientError {
		return resp, ErrInvalidClientCredentialsError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2InvalidRequestError {
		return resp, ErrInvalidRequestError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2InvalidGrantError {
		return resp, ErrInvalidGrantError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2UnsupportedResponseTypeError {
		return resp, ErrUnsupportedResponseTypeError
	}
	if resp.Error != "" {
		return resp, ErrUnexpectedError
	}

	return resp, nil
}

// ExchangeGoogleIDToken uses the passed ID token from Google to obtain a new
// access token and refresh token from the oauth2 service.
func (o OAuth2Service) ExchangeGoogleIDToken(ctx context.Context, token string, scopes []string) (OAuth2Response, error) {
	if token == "" {
		return OAuth2Response{}, ErrOAuth2RequestMissingToken
	}
	vals := url.Values{}
	vals.Set("grant_type", "google_id")
	vals.Set("id_token", token)
	if len(scopes) > 0 {
		vals.Set("scope", strings.Join(scopes, " "))
	}
	buf := bytes.NewBuffer([]byte(vals.Encode()))
	req, err := o.client.NewRequest(ctx, http.MethodPost, o.buildURL("/token"), buf)
	if err != nil {
		return OAuth2Response{}, fmt.Errorf("error constructing request: %w", err)
	}
	err = o.client.AddClientCredentials(req)
	if err != nil {
		return OAuth2Response{}, err
	}
	res, err := o.client.Do(req)
	if err != nil {
		return OAuth2Response{}, fmt.Errorf("error making request: %w", err)
	}

	resp, err := oauthResponse(res)
	if err != nil {
		return OAuth2Response{}, err
	}

	if res.StatusCode == http.StatusInternalServerError &&
		resp.Error == oauth2ServerError {
		return resp, ErrServerError
	}
	if res.StatusCode == http.StatusUnauthorized &&
		resp.Error == oauth2InvalidClientError {
		return resp, ErrInvalidClientCredentialsError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2InvalidRequestError {
		return resp, ErrInvalidRequestError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2InvalidGrantError {
		return resp, ErrInvalidGrantError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2UnsupportedResponseTypeError {
		return resp, ErrUnsupportedResponseTypeError
	}
	if resp.Error != "" {
		return resp, ErrUnexpectedError
	}
	return resp, nil
}

// SendEmail requests an authentication email be sent to the specified email
// address to kick off the email login flow.
func (o OAuth2Service) SendEmail(ctx context.Context, email string, scopes []string) error {
	if email == "" {
		return ErrOAuth2RequestMissingEmail
	}
	vals := url.Values{}
	vals.Set("response_type", "email")
	vals.Set("email", email)
	if len(scopes) > 0 {
		vals.Set("scope", strings.Join(scopes, " "))
	}
	buf := bytes.NewBuffer([]byte(vals.Encode()))
	req, err := o.client.NewRequest(ctx, http.MethodPost, o.buildURL("/authorize"), buf)
	if err != nil {
		return fmt.Errorf("error constructing request: %w", err)
	}
	err = o.client.AddClientCredentials(req)
	if err != nil {
		return err
	}
	res, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}

	// if we get a StatusNoContent response, everything went fine
	// we can bail now
	if res.StatusCode == http.StatusNoContent {
		return nil
	}

	// if we get any other response, we need to decode the response
	// and figure out what went wrong so we can surface a useful error
	resp, err := oauthResponse(res)
	if err != nil {
		return err
	}

	if res.StatusCode == http.StatusInternalServerError &&
		resp.Error == oauth2ServerError {
		return ErrServerError
	}
	if res.StatusCode == http.StatusUnauthorized &&
		resp.Error == oauth2InvalidClientError {
		return ErrInvalidClientCredentialsError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2InvalidRequestError {
		return ErrInvalidRequestError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2InvalidGrantError {
		return ErrInvalidGrantError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2UnsupportedResponseTypeError {
		return ErrUnsupportedResponseTypeError
	}
	if resp.Error != "" {
		return ErrUnexpectedError
	}
	return ErrUnexpectedBody
}

// ExchangeEmailCode uses the passed code, obtained from an authentication
// email, to obtain a new access token and refresh token from the oauth2
// service.
func (o OAuth2Service) ExchangeEmailCode(ctx context.Context, code string) (OAuth2Response, error) {
	if code == "" {
		return OAuth2Response{}, ErrOAuth2RequestMissingCode
	}
	v := url.Values{}
	v.Set("grant_type", "email")
	v.Set("code", code)
	buf := bytes.NewBuffer([]byte(v.Encode()))
	req, err := o.client.NewRequest(ctx, http.MethodPost, o.buildURL("/token"), buf)
	if err != nil {
		return OAuth2Response{}, fmt.Errorf("error constructing request: %w", err)
	}
	err = o.client.AddClientCredentials(req)
	if err != nil {
		return OAuth2Response{}, err
	}
	res, err := o.client.Do(req)
	if err != nil {
		return OAuth2Response{}, fmt.Errorf("error making request: %w", err)
	}

	// if we get any other response, we need to decode the response
	// and figure out what went wrong so we can surface a useful error
	resp, err := oauthResponse(res)
	if err != nil {
		return OAuth2Response{}, err
	}

	if res.StatusCode == http.StatusInternalServerError &&
		resp.Error == oauth2ServerError {
		return resp, ErrServerError
	}
	if res.StatusCode == http.StatusUnauthorized &&
		resp.Error == oauth2InvalidClientError {
		return resp, ErrInvalidClientCredentialsError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2InvalidRequestError {
		return resp, ErrInvalidRequestError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2InvalidGrantError {
		return resp, ErrInvalidGrantError
	}
	if res.StatusCode == http.StatusBadRequest &&
		resp.Error == oauth2UnsupportedResponseTypeError {
		return resp, ErrUnsupportedResponseTypeError
	}
	if resp.Error != "" {
		return resp, ErrUnexpectedError
	}
	return resp, nil
}
