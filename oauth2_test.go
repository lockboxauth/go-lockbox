package lockbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"yall.in"
	testinglog "yall.in/testing"
)

func TestOAuth2ExchangeRefreshToken_oneScope(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/token")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient", "veryverysecret")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type":    []string{"refresh_token"},
			"refresh_token": []string{"mytesttoken"},
			"scope":         []string{"https://scopes.lockbox.dev/test"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/test"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})

	resp, err := client.OAuth2.ExchangeRefreshToken(ctx, "mytesttoken", []string{
		"https://scopes.lockbox.dev/test",
	})
	if err != nil {
		t.Fatalf("Error exchanging token: %s", err)
	}
	if diff := cmp.Diff(OAuth2Response{
		AccessToken:  "new_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    1234,
		RefreshToken: "new_refresh_token",
		Scope:        "https://scopes.lockbox.dev/test",
	}, resp); diff != "" {
		t.Errorf("Response mismatch (-wanted, +got): %s", diff)
	}
}

func TestOAuth2ExchangeRefreshToken_noScope(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/token")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient", "veryverysecret")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type":    []string{"refresh_token"},
			"refresh_token": []string{"mytesttoken"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/default https://scopes.lockbox.dev/default2"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})

	resp, err := client.OAuth2.ExchangeRefreshToken(ctx, "mytesttoken", nil)
	if err != nil {
		t.Fatalf("Error exchanging token: %s", err)
	}
	if diff := cmp.Diff(OAuth2Response{
		AccessToken:  "new_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    1234,
		RefreshToken: "new_refresh_token",
		Scope:        "https://scopes.lockbox.dev/default https://scopes.lockbox.dev/default2",
	}, resp); diff != "" {
		t.Errorf("Response mismatch (-wanted, +got): %s", diff)
	}
}

func TestOAuth2ExchangeRefreshToken_threeScopes(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/token")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient", "veryverysecret")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type":    []string{"refresh_token"},
			"refresh_token": []string{"mytesttoken"},
			"scope":         []string{"https://scopes.lockbox.dev/test1 https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/test1 https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})

	resp, err := client.OAuth2.ExchangeRefreshToken(ctx, "mytesttoken", []string{
		"https://scopes.lockbox.dev/test1",
		"https://scopes.lockbox.dev/test2",
		"https://scopes.lockbox.dev/test3",
	})
	if err != nil {
		t.Fatalf("Error exchanging token: %s", err)
	}
	if diff := cmp.Diff(OAuth2Response{
		AccessToken:  "new_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    1234,
		RefreshToken: "new_refresh_token",
		Scope:        "https://scopes.lockbox.dev/test1 https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3",
	}, resp); diff != "" {
		t.Errorf("Response mismatch (-wanted, +got): %s", diff)
	}
}

func TestOAuth2ExchangeRefreshToken_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpectedError": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "foo"}`),
			err:    ErrUnexpectedError,
		},
		"serverError": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"error": "server_error"}`),
			err:    ErrServerError,
		},
		"invalidClient": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"error": "invalid_client"}`),
			err:    ErrInvalidClientCredentialsError,
		},
		"invalidRequest": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "invalid_request"}`),
			err:    ErrInvalidRequestError,
		},
		"invalidGrant": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "invalid_grant"}`),
			err:    ErrInvalidGrantError,
		},
		"unsupportedResponseType": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "unsupported_response_type"}`),
			err:    ErrUnsupportedResponseTypeError,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, ClientCredentials{
				ID:     "testClient",
				Secret: "veryverysecret",
			})

			_, err := client.OAuth2.ExchangeRefreshToken(ctx, "my-test-token", nil)
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestOAuth2ExchangeRefreshToken_missingToken(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"error": "invalid_grant"}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})
	_, err := client.OAuth2.ExchangeRefreshToken(ctx, "", nil)
	if err != ErrOAuth2RequestMissingToken {
		t.Errorf("Expected error %v, got %v instead", ErrOAuth2RequestMissingToken, err)
	}
}

func TestOAuth2ExchangeGoogleIDToken_oneScope(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/token")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient", "veryverysecret")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type": []string{"google_id"},
			"id_token":   []string{"mytesttoken"},
			"scope":      []string{"https://scopes.lockbox.dev/test"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/test"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})

	resp, err := client.OAuth2.ExchangeGoogleIDToken(ctx, "mytesttoken", []string{
		"https://scopes.lockbox.dev/test",
	})
	if err != nil {
		t.Fatalf("Error exchanging token: %s", err)
	}
	if diff := cmp.Diff(OAuth2Response{
		AccessToken:  "new_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    1234,
		RefreshToken: "new_refresh_token",
		Scope:        "https://scopes.lockbox.dev/test",
	}, resp); diff != "" {
		t.Errorf("Response mismatch (-wanted, +got): %s", diff)
	}
}

func TestOAuth2ExchangeGoogleIDToken_noScope(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/token")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient", "veryverysecret")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type": []string{"google_id"},
			"id_token":   []string{"mytesttoken"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/default1 https://scopes.lockbox.dev/default2"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})

	resp, err := client.OAuth2.ExchangeGoogleIDToken(ctx, "mytesttoken", nil)
	if err != nil {
		t.Fatalf("Error exchanging token: %s", err)
	}
	if diff := cmp.Diff(OAuth2Response{
		AccessToken:  "new_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    1234,
		RefreshToken: "new_refresh_token",
		Scope:        "https://scopes.lockbox.dev/default1 https://scopes.lockbox.dev/default2",
	}, resp); diff != "" {
		t.Errorf("Response mismatch (-wanted, +got): %s", diff)
	}
}

func TestOAuth2ExchangeGoogleIDToken_threeScopes(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/token")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient", "veryverysecret")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type": []string{"google_id"},
			"id_token":   []string{"mytesttoken"},
			"scope":      []string{"https://scopes.lockbox.dev/test https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/test https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})

	resp, err := client.OAuth2.ExchangeGoogleIDToken(ctx, "mytesttoken", []string{
		"https://scopes.lockbox.dev/test",
		"https://scopes.lockbox.dev/test2",
		"https://scopes.lockbox.dev/test3",
	})
	if err != nil {
		t.Fatalf("Error exchanging token: %s", err)
	}
	if diff := cmp.Diff(OAuth2Response{
		AccessToken:  "new_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    1234,
		RefreshToken: "new_refresh_token",
		Scope:        "https://scopes.lockbox.dev/test https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3",
	}, resp); diff != "" {
		t.Errorf("Response mismatch (-wanted, +got): %s", diff)
	}
}

func TestOAuth2ExchangeGoogleIDToken_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpectedError": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "foo"}`),
			err:    ErrUnexpectedError,
		},
		"serverError": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"error": "server_error"}`),
			err:    ErrServerError,
		},
		"invalidClient": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"error": "invalid_client"}`),
			err:    ErrInvalidClientCredentialsError,
		},
		"invalidRequest": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "invalid_request"}`),
			err:    ErrInvalidRequestError,
		},
		"invalidGrant": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "invalid_grant"}`),
			err:    ErrInvalidGrantError,
		},
		"unsupportedResponseType": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "unsupported_response_type"}`),
			err:    ErrUnsupportedResponseTypeError,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, ClientCredentials{
				ID:     "testClient",
				Secret: "veryverysecret",
			})

			_, err := client.OAuth2.ExchangeGoogleIDToken(ctx, "my-test-token", nil)
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestOAuth2ExchangeGoogleIDToken_missingToken(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"error": "invalid_grant"}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})
	_, err := client.OAuth2.ExchangeGoogleIDToken(ctx, "", nil)
	if err != ErrOAuth2RequestMissingToken {
		t.Errorf("Expected error %v, got %v instead", ErrOAuth2RequestMissingToken, err)
	}
}

func TestOAuth2SendEmail_oneScope(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/authorize")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient", "veryverysecret")
		checkURLFormEncodedBody(t, r, url.Values{
			"response_type": []string{"email"},
			"email":         []string{"test@lockbox.dev"},
			"scope":         []string{"https://scopes.lockbox.dev/test"},
		})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})

	err := client.OAuth2.SendEmail(ctx, "test@lockbox.dev", []string{
		"https://scopes.lockbox.dev/test",
	})
	if err != nil {
		t.Fatalf("Error kicking off email flow: %s", err)
	}
}

func TestOAuth2SendEmail_noScope(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/authorize")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient", "veryverysecret")
		checkURLFormEncodedBody(t, r, url.Values{
			"response_type": []string{"email"},
			"email":         []string{"test@lockbox.dev"},
		})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})

	err := client.OAuth2.SendEmail(ctx, "test@lockbox.dev", nil)
	if err != nil {
		t.Fatalf("Error kicking off email flow: %s", err)
	}
}

func TestOAuth2SendEmail_threeScopes(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/authorize")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient", "veryverysecret")
		checkURLFormEncodedBody(t, r, url.Values{
			"response_type": []string{"email"},
			"email":         []string{"test@lockbox.dev"},
			"scope":         []string{"https://scopes.lockbox.dev/test https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"},
		})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})

	err := client.OAuth2.SendEmail(ctx, "test@lockbox.dev", []string{
		"https://scopes.lockbox.dev/test",
		"https://scopes.lockbox.dev/test2",
		"https://scopes.lockbox.dev/test3",
	})
	if err != nil {
		t.Fatalf("Error kicking off email flow: %s", err)
	}
}

func TestOAuth2SendEmail_missingEmail(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusNoContent, nil)
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient",
		Secret: "veryverysecret",
	})
	err := client.OAuth2.SendEmail(ctx, "", nil)
	if err != ErrOAuth2RequestMissingEmail {
		t.Errorf("Expected error %v, got %v instead", ErrOAuth2RequestMissingEmail, err)
	}
}

func TestOAuth2SendEmail_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpectedError": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "foo"}`),
			err:    ErrUnexpectedError,
		},
		"serverError": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"error": "server_error"}`),
			err:    ErrServerError,
		},
		"invalidClient": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"error": "invalid_client"}`),
			err:    ErrInvalidClientCredentialsError,
		},
		"invalidRequest": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "invalid_request"}`),
			err:    ErrInvalidRequestError,
		},
		"invalidGrant": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "invalid_grant"}`),
			err:    ErrInvalidGrantError,
		},
		"unsupportedResponseType": {
			status: http.StatusBadRequest,
			body:   []byte(`{"error": "unsupported_response_type"}`),
			err:    ErrUnsupportedResponseTypeError,
		},
		"unexpectedBody": {
			status: http.StatusOK,
			body:   []byte(`{"errors": [{"field": "/whoops"}]}`),
			err:    ErrUnexpectedBody,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, ClientCredentials{
				ID:     "testClient",
				Secret: "veryverysecret",
			})

			err := client.OAuth2.SendEmail(ctx, "test@lockbox.dev", nil)
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

// TODO: test happy path for exchanging email code
// TODO: test unhappy paths for exchanging email code
