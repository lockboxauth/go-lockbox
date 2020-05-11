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
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"lockbox.dev/hmac"
	"yall.in"

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

	// ErrNoScopesHMACSecretSet is returned when the Client tries to make
	// an HMAC request to the scopes service but is not configured with an
	// HMAC secret
	ErrNoScopesHMACSecretSet = errors.New("no HMAC secret for the scopes service set")

	// ErrNoScopesHMACMaxSkewSet is returned when the Client tries to make
	// an HMAC request to the scopes service but is not configured with an
	// HMAC max skew
	ErrNoScopesHMACMaxSkewSet = errors.New("no HMAC max skew for the scopes service set")

	// ErrNoScopesHMACOrgKeySet is returned when the Client tries to make
	// an HMAC request to the scopes service but is not configured with an
	// HMAC org key
	ErrNoScopesHMACOrgKeySet = errors.New("no HMAC org key for the scopes service set")

	// ErrNoScopesHMACKeySet is returned when the Client tries to make an
	// HMAC request to the scopes service but is not configured with an
	// HMAC key
	ErrNoScopesHMACKeySet = errors.New("no HMAC key for the scopes service set")

	// ErrBothClientSecretAndRedirectURISet is return when the Client tries
	// to make a request using client credentials and both the redirect URI
	// and client secret are set
	ErrBothClientSecretAndRedirectURISet = errors.New("both client secret and redirect URI set")
)

// Client is an HTTP client that can make requests against Lockbox's various
// services and the services that use Lockbox for authentication.
type Client struct {
	client    *http.Client
	transport *loggingTransport
	baseURL   *url.URL

	clientID          string
	clientSecret      string
	clientRedirectURI string

	accessToken  string
	refreshToken string

	hmacs hmacAuths

	Accounts *AccountsService
	Clients  *ClientsService
	OAuth2   *OAuth2Service
	Scopes   *ScopesService
}

type hmacAuths struct {
	clients HMACAuth
	scopes  HMACAuth
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

type loggingTransport struct {
	active bool
	t      http.RoundTripper
	log    *yall.Logger
	mu     sync.RWMutex
}

func (l *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var active bool
	l.mu.RLock()
	active = l.active
	l.mu.RUnlock()

	if active {
		reqBody, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			l.log.WithError(err).Error("error dumping request")
		} else {
			l.log.WithField("request", string(reqBody)).Debug("making request")
		}
	}
	resp, err := l.t.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	if active {
		respData, err := httputil.DumpResponse(resp, true)
		if err != nil {
			l.log.WithError(err).Error("error dumping response")
		} else {
			l.log.WithField("response", string(respData)).Debug("got response")
		}
	}

	return resp, nil
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
	Scopes  HMACAuth
}

// Apply configures the Client `c` with the HMAC credentials set in `h`.
func (h HMACCredentials) Apply(c *Client) {
	c.hmacs.clients = h.Clients
	c.hmacs.scopes = h.Scopes
}

// NewClient returns a new client capable of interacting with Lockbox services.
// The baseURL specified should point to the URL that lockbox-apid is serving
// at. Any number of AuthMethods can be passed to configure the client,
// including none.
func NewClient(ctx context.Context, baseURL string, auth ...AuthMethod) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing baseURL: %w", err)
	}
	c := &Client{
		client:  cleanhttp.DefaultPooledClient(),
		baseURL: base,
	}

	c.transport = &loggingTransport{
		log: yall.FromContext(ctx),
		t:   c.client.Transport,
	}
	c.client.Transport = c.transport
	for _, method := range auth {
		method.Apply(c)
	}

	c.Accounts = &AccountsService{
		BasePath: accountsServiceDefaultBasePath,
		client:   c,
	}

	c.Clients = &ClientsService{
		BasePath: clientsServiceDefaultBasePath,
		client:   c,
	}

	c.OAuth2 = &OAuth2Service{
		BasePath: oauth2ServiceDefaultBasePath,
		client:   c,
	}

	c.Scopes = &ScopesService{
		BasePath: scopesServiceDefaultBasePath,
		client:   c,
	}
	return c, nil
}

// RefreshTokens exchanges the token credentials configured on `c` for new
// token credentials, and configures `c` with the new token credentials.
func (c *Client) RefreshTokens(ctx context.Context, scopes []string) error {
	if c.refreshToken == "" {
		return ErrNoRefreshTokenSet
	}
	resp, err := c.OAuth2.ExchangeRefreshToken(ctx, c.refreshToken, scopes)
	if err != nil {
		return fmt.Errorf("error exchanging refresh token: %w", err)
	}
	c.accessToken = resp.AccessToken
	c.refreshToken = resp.RefreshToken
	return nil
}

// EnableLogs turns on request and response logging for the client, for
// debugging purposes. This should probably not be called in production, as
// sensitive values will be logged.
func (c *Client) EnableLogs() {
	c.transport.mu.Lock()
	defer c.transport.mu.Unlock()
	c.transport.active = true
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
	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "go-lockbox/"+getVersion())
	return req, nil
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
	if c.clientSecret != "" {
		r.SetBasicAuth(c.clientID, c.clientSecret)
		return nil
	}
	values := r.URL.Query()
	values.Set("client_id", c.clientID)
	values.Set("redirect_uri", c.clientRedirectURI)
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
	return c.makeHMACRequest(r, c.hmacs.clients)
}

// MakeScopesHMACRequest signs an *http.Request so it can be executed against
// the Scopes service.
func (c Client) MakeScopesHMACRequest(r *http.Request) error {
	if len(c.hmacs.scopes.Secret) == 0 {
		return ErrNoScopesHMACSecretSet
	}
	if c.hmacs.scopes.MaxSkew == 0 {
		return ErrNoScopesHMACMaxSkewSet
	}
	if c.hmacs.scopes.OrgKey == "" {
		return ErrNoScopesHMACOrgKeySet
	}
	if c.hmacs.scopes.Key == "" {
		return ErrNoScopesHMACKeySet
	}
	return c.makeHMACRequest(r, c.hmacs.scopes)
}

func (c Client) makeHMACRequest(r *http.Request, auth HMACAuth) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("error reading request body: %w", err)
	}
	buf := bytes.NewBuffer(body)
	r.Body = ioutil.NopCloser(buf)
	signer := hmac.Signer{
		Secret:  []byte(auth.Secret),
		MaxSkew: auth.MaxSkew,
		OrgKey:  auth.OrgKey,
		Key:     auth.Key,
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
