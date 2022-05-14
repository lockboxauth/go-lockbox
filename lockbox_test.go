package lockbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-uuid"
	"github.com/nsf/jsondiff"
	"yall.in"
	testinglog "yall.in/testing"

	"lockbox.dev/hmac"
)

type errorTest struct {
	status int
	body   []byte
	err    error
}

func uuidOrFail(t *testing.T) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("Unexpected error generating ID: %s", err.Error())
	}
	return id
}

func mustWrite(t *testing.T, w http.ResponseWriter, b []byte) {
	if _, err := w.Write(b); err != nil {
		t.Errorf("Error writing response: %s", err)
	}
}

func staticResponseServer(t *testing.T, code int, body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		mustWrite(t, w, body)
	}))
}

func testClient(ctx context.Context, t *testing.T, baseURL string, auth ...AuthMethod) *Client {
	client, err := NewClient(ctx, baseURL, auth...)
	if err != nil {
		t.Fatalf("Error creating client: %s", err)
	}
	if testing.Verbose() {
		client.EnableLogs()
	}
	return client
}

func checkURL(t *testing.T, r *http.Request, expected string) {
	t.Helper()
	if r.URL.String() != expected {
		t.Errorf("Expected URL to be %q, got %q", expected, r.URL.String())
	}
}

func checkMethod(t *testing.T, r *http.Request, expected string) {
	t.Helper()
	if r.Method != expected {
		t.Errorf("Expected method to be %q, got %q", expected, r.Method)
	}
}

func checkJSONBody(t *testing.T, r *http.Request, expected string) {
	t.Helper()
	req, err := cloneRequest(r)
	if err != nil {
		t.Fatalf("Error cloning request: %s", err)
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Error reading body: %s", err)
	}
	defer func() {
		if err = req.Body.Close(); err != nil {
			t.Errorf("Error closing body: %v", err)
		}
	}()
	opts := jsondiff.DefaultConsoleOptions()
	diff, output := jsondiff.Compare(body, []byte(expected), &opts)
	if diff != jsondiff.FullMatch {
		t.Errorf("Body didn't match expectation: %s", output)
	}
}

func checkURLFormEncodedBody(t *testing.T, r *http.Request, expected url.Values) {
	t.Helper()
	req, err := cloneRequest(r)
	if err != nil {
		t.Fatalf("Error cloning request: %s", err)
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Error reading body: %s", err)
	}
	defer func() {
		if err = req.Body.Close(); err != nil {
			t.Errorf("Error closing body: %v", err)
		}
	}()
	got, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatalf("Error parsing body as URL-encoded query string: %s", err)
	}
	if diff := cmp.Diff(expected, got); diff != "" {
		t.Errorf("Body didn't match expectation (-wanted, +got): %s", diff)
	}
}

func checkAuthorization(t *testing.T, r *http.Request, expected string) {
	t.Helper()
	got := r.Header.Get("Authorization")
	if got != expected {
		t.Errorf("Expected Authorization header to be %q, got %q", expected, got)
	}
}

func checkBearerToken(t *testing.T, r *http.Request, expected string) {
	t.Helper()
	checkAuthorization(t, r, "Bearer "+expected)
}

func checkBasicAuth(t *testing.T, r *http.Request, username, password string) {
	t.Helper()
	user, pass, ok := r.BasicAuth()
	if !ok && (username != "" || password != "") {
		t.Errorf("username expected to be %q, password expected to be %q, but no basic auth set", username, password)
	}
	if ok && username == "" && password == "" {
		t.Errorf("no basic auth expected to be set, but got username of %q and password of %q", user, pass)
	}
	if user != username {
		t.Errorf("expected username to be %q, got %q", username, user)
	}
	if pass != password {
		t.Errorf("expected password to be %q, got %q", password, pass)
	}
}

func cloneRequest(r *http.Request) (*http.Request, error) {
	req := r.Clone(context.Background())
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading request body: %w", err)
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	return req, nil
}

func checkHMACAuthorization(t *testing.T, r *http.Request, auth HMACAuth) {
	t.Helper()
	req, err := cloneRequest(r)
	if err != nil {
		t.Fatalf("Error cloning request: %s", err)
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Error reading body: %s", err)
	}
	defer func() {
		if err = req.Body.Close(); err != nil {
			t.Errorf("Error closing body: %v", err)
		}
	}()
	hash := base64.StdEncoding.EncodeToString(sha256.New().Sum(body))
	signer := hmac.Signer{
		Secret:  auth.Secret,
		MaxSkew: auth.MaxSkew,
		OrgKey:  auth.OrgKey,
		Key:     auth.Key,
	}
	err = signer.AuthenticateRequest(req, hash)
	if err != nil {
		t.Errorf("Error authenticating request: %s", err)
		return
	}
}

func TestUserAgent(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	type testCase struct {
		pre      []string
		app      []string
		expected string
	}
	base := "go-lockbox/" + getVersion()
	t.Logf("User-Agent base: %q", base)
	cases := map[string]testCase{
		"default":  {expected: base},
		"prepend1": {pre: []string{"test/1.0.0"}, expected: "test/1.0.0 " + base},
		"prepend3": {pre: []string{"test/1.0.0", "test2/1.2.3", "test3/4.5.6"}, expected: "test/1.0.0 test2/1.2.3 test3/4.5.6 " + base},
		"append1":  {app: []string{"test/1.0.0"}, expected: base + " test/1.0.0"},
		"append3":  {app: []string{"test/1.0.0", "test2/1.2.3", "test3/4.5.6"}, expected: base + " test/1.0.0 test2/1.2.3 test3/4.5.6"},
		"both1":    {app: []string{"test/1.0.0"}, pre: []string{"test2/1.2.3"}, expected: "test2/1.2.3 " + base + " test/1.0.0"},
		"both3":    {app: []string{"test/1.0.0", "test2/1.2.3", "test3/4.5.6"}, pre: []string{"test4/1.0.0", "test5/1.2.3", "test6/4.5.6"}, expected: "test4/1.0.0 test5/1.2.3 test6/4.5.6 " + base + " test/1.0.0 test2/1.2.3 test3/4.5.6"},
	}

	for name, test := range cases {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := testClient(ctx, t, "https://example.com")
			for _, s := range test.pre {
				client.PrependToUserAgent(s)
			}
			for _, s := range test.app {
				client.AppendToUserAgent(s)
			}
			ua := client.buildUA()
			if ua != test.expected {
				t.Errorf("Expected user agent to be %q, got %q", test.expected, ua)
			}
		})
	}
}
