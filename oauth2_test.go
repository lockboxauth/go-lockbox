package lockbox

import (
	"context"
	"errors"
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
		checkBasicAuth(t, r, "testClient_exchange_oneScope", "veryverysecret_exchange_oneScope")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type":    []string{"refresh_token"},
			"refresh_token": []string{"mytesttoken"},
			"scope":         []string{"https://scopes.lockbox.dev/test"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/test"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_exchange_oneScope",
		Secret: "veryverysecret_exchange_oneScope",
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
		checkBasicAuth(t, r, "testClient_exchange_noScope", "veryverysecret_exchange_noScope")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type":    []string{"refresh_token"},
			"refresh_token": []string{"mytesttoken"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/default https://scopes.lockbox.dev/default2"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_exchange_noScope",
		Secret: "veryverysecret_exchange_noScope",
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
		checkBasicAuth(t, r, "testClient_exchange_threeScopes", "veryverysecret_exchange_threeScopes")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type":    []string{"refresh_token"},
			"refresh_token": []string{"mytesttoken"},
			"scope":         []string{"https://scopes.lockbox.dev/test1 https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/test1 https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_exchange_threeScopes",
		Secret: "veryverysecret_exchange_threeScopes",
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
				ID:     "testClient_exchange_errors",
				Secret: "veryverysecret_exchange_errors",
			})

			_, err := client.OAuth2.ExchangeRefreshToken(ctx, "my-test-token", nil)
			if !errors.Is(err, test.err) {
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
		ID:     "testClient_exchange_missing",
		Secret: "veryverysecret_exchange_missing",
	})
	_, err := client.OAuth2.ExchangeRefreshToken(ctx, "", nil)
	if !errors.Is(err, ErrOAuth2RequestMissingToken) {
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
		checkBasicAuth(t, r, "testClient_google_oneScope", "veryverysecret_google_oneScope")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type": []string{"google_id"},
			"id_token":   []string{"mytesttoken"},
			"scope":      []string{"https://scopes.lockbox.dev/test"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/test"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_google_oneScope",
		Secret: "veryverysecret_google_oneScope",
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
		checkBasicAuth(t, r, "testClient_google_noScope", "veryverysecret_google_noScope")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type": []string{"google_id"},
			"id_token":   []string{"mytesttoken"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/default1 https://scopes.lockbox.dev/default2"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_google_noScope",
		Secret: "veryverysecret_google_noScope",
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
		checkBasicAuth(t, r, "testClient_google_threeScopes", "veryverysecret_google_threeScopes")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type": []string{"google_id"},
			"id_token":   []string{"mytesttoken"},
			"scope":      []string{"https://scopes.lockbox.dev/test https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/test https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_google_threeScopes",
		Secret: "veryverysecret_google_threeScopes",
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
				ID:     "testClient_google_errors",
				Secret: "veryverysecret_google_errors",
			})

			_, err := client.OAuth2.ExchangeGoogleIDToken(ctx, "my-test-token", nil)
			if !errors.Is(err, test.err) {
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
		ID:     "testClient_google_missing",
		Secret: "veryverysecret_google_missing",
	})
	_, err := client.OAuth2.ExchangeGoogleIDToken(ctx, "", nil)
	if !errors.Is(err, ErrOAuth2RequestMissingToken) {
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
		checkBasicAuth(t, r, "testClient_email_oneScope", "veryverysecret_email_oneScope")
		checkURLFormEncodedBody(t, r, url.Values{
			"response_type": []string{"email"},
			"email":         []string{"test@lockbox.dev"},
			"scope":         []string{"https://scopes.lockbox.dev/test"},
		})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_email_oneScope",
		Secret: "veryverysecret_email_oneScope",
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
		checkBasicAuth(t, r, "testClient_email_noScope", "veryverysecret_email_noScope")
		checkURLFormEncodedBody(t, r, url.Values{
			"response_type": []string{"email"},
			"email":         []string{"test@lockbox.dev"},
		})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_email_noScope",
		Secret: "veryverysecret_email_noScope",
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
		checkBasicAuth(t, r, "testClient_email_threeScopes", "veryverysecret_email_threeScopes")
		checkURLFormEncodedBody(t, r, url.Values{
			"response_type": []string{"email"},
			"email":         []string{"test@lockbox.dev"},
			"scope":         []string{"https://scopes.lockbox.dev/test https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"},
		})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_email_threeScopes",
		Secret: "veryverysecret_email_threeScopes",
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
		ID:     "testClient_email_missing",
		Secret: "veryverysecret_email_missing",
	})
	err := client.OAuth2.SendEmail(ctx, "", nil)
	if !errors.Is(err, ErrOAuth2RequestMissingEmail) {
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
				ID:     "testClient_email_errors",
				Secret: "veryverysecret_email_errors",
			})

			err := client.OAuth2.SendEmail(ctx, "test@lockbox.dev", nil)
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestOAuth2ExchangeEmailCode(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/oauth2/v1/token")
		checkMethod(t, r, http.MethodPost)
		checkBasicAuth(t, r, "testClient_emailcode", "veryverysecret_emailcode")
		checkURLFormEncodedBody(t, r, url.Values{
			"grant_type": []string{"email"},
			"code":       []string{"mytestcode"},
		})
		mustWrite(t, w, []byte(`{"access_token": "new_access_token", "token_type": "Bearer", "expires_in": 1234, "refresh_token": "new_refresh_token", "scope": "https://scopes.lockbox.dev/test https://scopes.lockbox.dev/test2 https://scopes.lockbox.dev/test3"}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_emailcode",
		Secret: "veryverysecret_emailcode",
	})

	resp, err := client.OAuth2.ExchangeEmailCode(ctx, "mytestcode")
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

func TestOAuth2ExchangeEmailCode_missingCode(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"error": "invalid_grant"}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, ClientCredentials{
		ID:     "testClient_emailcode_missing",
		Secret: "veryverysecret_emailcode_missing",
	})
	_, err := client.OAuth2.ExchangeEmailCode(ctx, "")
	if !errors.Is(err, ErrOAuth2RequestMissingCode) {
		t.Errorf("Expected error %v, got %v instead", ErrOAuth2RequestMissingCode, err)
	}
}

func TestOAuth2ExchangeEmailCode_errors(t *testing.T) {
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
				ID:     "testClient_emailcode_errors",
				Secret: "veryverysecret_emailcode_errors",
			})

			_, err := client.OAuth2.ExchangeEmailCode(ctx, "testcode")
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}
