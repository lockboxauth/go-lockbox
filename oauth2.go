package lockbox

import (
	"context"
	"errors"
)

const (
	oauth2ServiceDefaultBasePath = "/oauth2/v1/"
)

// OAuth2Service is the oauth2 service. Set the BasePath to modify where
// requests will be sent relative to the Client's base URL. OAuth2Service
// should only be instantiated by calling NewClient.
type OAuth2Service struct {
	BasePath string
	client   *Client
}

type OAuth2Response struct{}

func (o OAuth2Service) ExchangeRefreshToken(ctx context.Context, token string) (OAuth2Response, error) {
	// TODO: implement exchanging a refresh token for a new token
	return OAuth2Response{}, errors.New("not implemented yet")
}

func (o OAuth2Service) ExchangeGoogleIDToken(ctx context.Context, token string) (OAuth2Response, error) {
	// TODO: implement exchanging a Google ID token for a new token
	return OAuth2Response{}, errors.New("not implemented yet")
}

func (o OAuth2Service) SendEmail(ctx context.Context, email string) error {
	// TODO: implement kicking off the email auth flow
	return errors.New("not implemented yet")
}

func (o OAuth2Service) ExchangeEmailCode(ctx context.Context, code string) (OAuth2Response, error) {
	// TODO: implement exchanging an emailed code for a new token
	return OAuth2Response{}, errors.New("not implemented yet")
}
