package lockbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

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
)

// Client is an HTTP client that can make requests against Lockbox's various
// services and the services that use Lockbox for authentication.
type Client struct {
	client           *http.Client
	transport        *loggingTransport
	baseURL          *url.URL
	userAgentPrepend []string
	userAgentAppend  []string
	userAgentMu      *sync.RWMutex

	accessToken  string
	refreshToken string
	tokenMu      sync.RWMutex

	Accounts *AccountsService
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

type loggingTransport struct {
	active bool
	t      http.RoundTripper
	log    *yall.Logger
	mu     sync.RWMutex
}

// RoundTrip makes the http.Request using the http.RoundTripper associated with
// the loggingTransport, logging the request and response if its active
// property is set to true.
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

// NewClient returns a new client capable of interacting with Lockbox services.
// The baseURL specified should point to the URL that lockbox-apid is serving
// at. Any number of AuthMethods can be passed to configure the client,
// including none.
func NewClient(ctx context.Context, baseURL string, auth ...AuthMethod) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing baseURL: %w", err)
	}
	client := &Client{
		client:      cleanhttp.DefaultPooledClient(),
		baseURL:     base,
		userAgentMu: new(sync.RWMutex),
	}

	client.transport = &loggingTransport{
		log: yall.FromContext(ctx),
		t:   client.client.Transport,
	}
	client.client.Transport = client.transport
	for _, method := range auth {
		method.Apply(client)
	}

	client.Accounts = &AccountsService{
		BasePath: accountsServiceDefaultBasePath,
		client:   client,
	}

	return client, nil
}

// RefreshTokens exchanges the token credentials configured on `c` for new
// token credentials, and configures `c` with the new token credentials.
func (c *Client) RefreshTokens(_ context.Context) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.refreshToken == "" {
		return ErrNoRefreshTokenSet
	}
	// TODO: refresh tokens
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

// AppendToUserAgent adds the string to the end of the User-Agent header that
// will be sent with requests from this client.
func (c *Client) AppendToUserAgent(s string) {
	c.userAgentMu.Lock()
	c.userAgentAppend = append(c.userAgentAppend, s)
	c.userAgentMu.Unlock()
}

// PrependToUserAgent adds the string to the beginning of the User-Agent header
// that will be sent with requests from this client.
func (c *Client) PrependToUserAgent(s string) {
	c.userAgentMu.Lock()
	c.userAgentPrepend = append(c.userAgentPrepend, s)
	c.userAgentMu.Unlock()
}

// Do executes an *http.Request using the *http.Client associated with `c`.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// NewRequest builds a new *http.Request against the specified `path`, using
// the configured base URL of the client.
func (c *Client) NewRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("error parsing path: %w", err)
	}
	reqURL := c.baseURL.ResolveReference(u)
	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.buildUA())
	return req, nil
}

func (c *Client) buildUA() string {
	userAgent := "go-lockbox/" + getVersion()
	c.userAgentMu.RLock()
	uaAppend := strings.TrimSpace(strings.Join(c.userAgentAppend, " "))
	uaPrepend := strings.TrimSpace(strings.Join(c.userAgentPrepend, " "))
	c.userAgentMu.RUnlock()
	if uaPrepend != "" {
		userAgent = uaPrepend + " " + userAgent
	}
	if uaAppend != "" {
		userAgent = userAgent + " " + uaAppend
	}
	return userAgent
}

// AddTokenCredentials adds the configured tokens to `r` as credentials,
// authenticating the request.
func (c *Client) AddTokenCredentials(r *http.Request) error {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	if c.accessToken == "" {
		return ErrNoAccessTokenSet
	}
	r.Header.Set("Authorization", "Bearer "+c.accessToken)
	return nil
}

// GetTokens retrieves the currently set access and refresh tokens for the
// Client. It is meant to be used to persist the tokens to avoid authenticating
// on every Client instantiation; there should be no other reason to interact
// with the tokens this way.
func (c *Client) GetTokens() (access, refresh string) {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.accessToken, c.refreshToken
}
