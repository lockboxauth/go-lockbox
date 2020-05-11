package lockbox

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nsf/jsondiff"
)

type errorTest struct {
	status int
	body   []byte
	err    error
}

func staticResponseServer(code int, body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		w.Write(body)
	}))
}

func testClient(t *testing.T, ctx context.Context, url string, auth ...AuthMethod) *Client {
	client, err := NewClient(ctx, url, auth...)
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
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		t.Fatalf("Error reading body: %s", err)
	}
	opts := jsondiff.DefaultConsoleOptions()
	diff, output := jsondiff.Compare(body, []byte(expected), &opts)
	if diff != jsondiff.FullMatch {
		t.Errorf("Body didn't match expectation: %s", output)
	}
}

func checkAuthorization(t *testing.T, r *http.Request, expected string) {
	t.Helper()
	got := r.Header.Get("Authorization")
	if got != "Bearer test-access" {
		t.Errorf("Expected Authorization header to be %q, got %q", expected, got)
	}
}
