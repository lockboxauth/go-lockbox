package lockbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"lockbox.dev/hmac"

	"github.com/hashicorp/go-cleanhttp"
)

var (
	// ErrNoAccessTokenSet is returned when the Client tries to use an
	// access token but is not configured with one
	ErrNoAccessTokenSet = errors.New("no access token set")

	// ErrNoRefreshTokenSet is returned when the Client tries to use a
	// refresh token but is not configured with one
	ErrNoRefreshTokenSet = errors.New("no refresh token set")

	// ErrNoClientIDSet is returned when the Client tries to use a client
	// ID but is not configured with one
	ErrNoClientIDSet = errors.New("no client ID set")

	// ErrNoClientSecretSet is returned when the Client tries to use a
	// client secret but is not configured with one
	ErrNoClientSecretSet = errors.New("no client secret set")

	// ErrNoClientRedirectURISet is returned when the Client tries to use a
	// redirect URI but is not configured with one
	ErrNoClientRedirectURISet = errors.New("no client redirect URI set")

	// ErrNoClientsHMACSecretSet is returned when the Client tries to make
	// an HMAC request to the clients service but is not configured with an
	// HMAC secret
	ErrNoClientsHMACSecretSet = errors.New("no HMAC secret for the clients service set")

	// ErrNoClientsHMACMaxSkewSet is returned when the Client tries to make
	// an HMAC request to the clients service but is not configured with an
	// HMAC max skew
	ErrNoClientsHMACMaxSkewSet = errors.New("no HMAC max skew for the clients service set")

	// ErrNoClientsHMACOrgKeySet is returned when the Client tries to make
	// an HMAC request to the clients service but is not configured with an
	// HMAC org key
	ErrNoClientsHMACOrgKeySet = errors.New("no HMAC org key for the clients service set")

	// ErrNoClientsHMACKeySet is returned when the Client tries to make an
	// HMAC request to the clients service but is not configured with an
	// HMAC key
	ErrNoClientsHMACKeySet = errors.New("no HMAC key for the clients service set")

	// ErrBothClientSecretAndRedirectURISet is return when the Client tries
	// to make a request using client credentials and both the redirect URI
	// and client secret are set
	ErrBothClientSecretAndRedirectURISet = errors.New("both client secret and redirect URI set")
)

// Client is an HTTP client that can make requests against Lockbox's various
// services and the services that use Lockbox for authentication.
type Client struct {
	client  *http.Client
	baseURL *url.URL

	clientID          string
	clientSecret      string
	clientRedirectURI string

	accessToken  string
	refreshToken string

	hmacs hmacAuths
}

type hmacAuths struct {
	clients HMACAuth
}

// HMACAuth contains all the information necessary to authenticate against an
// HMAC-secured service, like the clients service.
type HMACAuth struct {
	// MaxSkew is the maximum amount of clock skew to accept
	MaxSkew time.Duration
	// OrgKey is the organization key the service is using
	OrgKey string
	// Key is the key ID the service is using
	Key string
	// Secret is the HMAC secret the service is using
	Secret []byte
}

// AuthMethod is a way of authenticating the Client. When constructing a
// Client, passed AuthMethods will configure the Client to authenticate with
// various services.
type AuthMethod interface {
	Apply(c *Client)
}

// AuthTokens configures the client with credentials necessary to authenticate
// against services that use token authentication, like services utilising
// Lockbox as an authentication service.
type AuthTokens struct {
	Access  string
	Refresh string
}

// Apply configures the Client `c` with the access and refresh tokens in `a`.
func (a AuthTokens) Apply(c *Client) {
	c.accessToken = a.Access
	c.refreshToken = a.Refresh
}

// ClientCredentials configures the client with credentials necessary to
// authenticate against services that use those credentials, like the oauth2
// service.
type ClientCredentials struct {
	ID          string
	Secret      string
	RedirectURI string
}

// Apply configures the Client `c` with the client ID, client secret, and
// redirect URI set on `creds`.
func (creds ClientCredentials) Apply(c *Client) {
	c.clientID = creds.ID
	c.clientSecret = creds.Secret
	c.clientRedirectURI = creds.RedirectURI
}

// HMACCredentials configures the Client with credentials necessary to
// authenticate against HMAC-secured endpoints, like the clients service.
type HMACCredentials struct {
	Clients HMACAuth
}

// Apply configures the Client `c` with the HMAC credentials set in `h`.
func (h HMACCredentials) Apply(c *Client) {
	c.hmacs.clients = h.Clients
}

// NewClient returns a new client capable of interacting with Lockbox services.
// The baseURL specified should point to the URL that lockbox-apid is serving
// at. Any number of AuthMethods can be passed to configure the client,
// including none.
func NewClient(baseURL string, auth ...AuthMethod) (Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return Client{}, fmt.Errorf("error parsing baseURL: %w", err)
	}
	c := Client{
		client:  cleanhttp.DefaultPooledClient(),
		baseURL: base,
	}
	for _, method := range auth {
		method.Apply(&c)
	}
	return c, nil
}

// RefreshTokens exchanges the token credentials configured on `c` for new
// token credentials, and configures `c` with the new token credentials.
func (c *Client) RefreshTokens(ctx context.Context) error {
	if c.refreshToken == "" {
		return ErrNoRefreshTokenSet
	}
	// TODO: refresh the tokens
	return nil
}

// Do executes an *http.Request using the *http.Client associated with `c`.
func (c Client) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// NewRequest builds a new *http.Request against the specified `path`, using
// the configured base URL of the client.
func (c Client) NewRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("error parsing path: %w", err)
	}
	reqURL := c.baseURL.ResolveReference(u)
	return http.NewRequestWithContext(ctx, method, reqURL.String(), body)
}

// AddClientCredentials adds the configured client credentials to `r`,
// authenticating the request. This is usually used for OAuth2 requests.
func (c Client) AddClientCredentials(r *http.Request) error {
	if c.clientID == "" {
		return ErrNoClientIDSet
	}
	if c.clientSecret == "" && c.clientRedirectURI == "" {
		return ErrNoClientSecretSet
	}
	if c.clientSecret != "" && c.clientRedirectURI == "" {
		return ErrBothClientSecretAndRedirectURISet
	}
	values := r.URL.Query()
	values.Set("client_id", c.clientID)
	if c.clientSecret != "" {
		r.SetBasicAuth(c.clientID, c.clientSecret)
	}
	if c.clientRedirectURI != "" {
		values.Set("redirect_uri", c.clientRedirectURI)
	}
	r.URL.RawQuery = values.Encode()
	return nil
}

// AddTokenCredentials adds the configured tokens to `r` as credentials,
// authenticating the request.
func (c Client) AddTokenCredentials(r *http.Request) error {
	if c.accessToken == "" {
		return ErrNoAccessTokenSet
	}
	r.Header.Set("Authorization", "Bearer "+c.accessToken)
	return nil
}

// MakeClientsHMACRequest signs an *http.Request so it can be executed against
// the Clients service.
func (c Client) MakeClientsHMACRequest(r *http.Request) error {
	if len(c.hmacs.clients.Secret) == 0 {
		return ErrNoClientsHMACSecretSet
	}
	if c.hmacs.clients.MaxSkew == 0 {
		return ErrNoClientsHMACMaxSkewSet
	}
	if c.hmacs.clients.OrgKey == "" {
		return ErrNoClientsHMACOrgKeySet
	}
	if c.hmacs.clients.Key == "" {
		return ErrNoClientsHMACKeySet
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("error reading request body: %w", err)
	}
	buf := bytes.NewBuffer(body)
	r.Body = ioutil.NopCloser(buf)
	signer := hmac.Signer{
		Secret:  []byte(c.hmacs.clients.Secret),
		MaxSkew: c.hmacs.clients.MaxSkew,
		OrgKey:  c.hmacs.clients.OrgKey,
		Key:     c.hmacs.clients.Key,
	}
	r.Header.Set("Date", time.Now().Format(time.RFC1123))
	r.Header.Set("Content-SHA256", base64.StdEncoding.EncodeToString(sha256.New().Sum(buf.Bytes())))
	sig := signer.Sign(r)
	r.Header.Set("Authorization", fmt.Sprintf("%s v1 %s:%s", signer.OrgKey, signer.Key, sig))
	return nil
}

// GetTokens retrieves the currently set access and refresh tokens for the
// Client. It is meant to be used to persist the tokens to avoid authenticating
// on every Client instantiation; there should be no other reason to interact
// with the tokens this way.
func (c Client) GetTokens() (access, refresh string) {
	return c.accessToken, c.refreshToken
}
