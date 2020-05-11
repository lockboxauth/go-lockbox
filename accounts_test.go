package lockbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"yall.in"
	testinglog "yall.in/testing"
)

func TestAccountsCreate_register(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1")
		checkMethod(t, r, http.MethodPost)
		checkJSONBody(t, r, `{"id": "test@lockbox.dev", "isRegistration": true, "createdAt": "0001-01-01T00:00:00Z", "lastSeenAt": "0001-01-01T00:00:00Z", "lastUsedAt": "0001-01-01T00:00:00Z"}`)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"accounts": [{"id": "test@lockbox.dev", "isRegistration": true, "createdAt": "` + timestamp + `", "lastSeenAt": "` + timestamp + `", "lastUsedAt": "` + timestamp + `", "profileID": "b9d7ed67-330b-481d-ad50-2208fe30b947"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL)

	account, err := client.Accounts.Create(ctx, Account{
		ID:             "test@lockbox.dev",
		IsRegistration: true,
	})
	if err != nil {
		t.Fatalf("Error registering account: %s", err)
	}
	if diff := cmp.Diff(Account{
		ID:             "test@lockbox.dev",
		IsRegistration: true,
		ProfileID:      "b9d7ed67-330b-481d-ad50-2208fe30b947",
		CreatedAt:      now,
		LastSeenAt:     now,
		LastUsedAt:     now,
	}, account); diff != "" {
		t.Errorf("Account mismatch (-wanted, +got): %s", diff)
	}
}

func TestAccountsCreate_addAccount(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1")
		checkMethod(t, r, http.MethodPost)
		checkAuthorization(t, r, "Bearer test-access")
		checkJSONBody(t, r, `{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "0001-01-01T00:00:00Z", "lastSeenAt": "0001-01-01T00:00:00Z", "lastUsedAt": "0001-01-01T00:00:00Z"}`)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"accounts": [{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "` + timestamp + `", "lastSeenAt": "` + timestamp + `", "lastUsedAt": "` + timestamp + `"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access",
		Refresh: "test-refresh",
	})

	account, err := client.Accounts.Create(ctx, Account{
		ID:        "test@lockbox.dev",
		ProfileID: "testing123",
	})
	if err != nil {
		t.Fatalf("Unexpected error adding account: %s", err)
	}
	if diff := cmp.Diff(Account{
		ID:             "test@lockbox.dev",
		ProfileID:      "testing123",
		IsRegistration: false,
		CreatedAt:      now,
		LastUsedAt:     now,
		LastSeenAt:     now,
	}, account); diff != "" {
		t.Errorf("Account mismatch (-wanted, +got): %s", diff)
	}
}

func TestAccountsCreate_noAccounts(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL)
	_, err := client.Accounts.Create(ctx, Account{
		ID:             "test@lockbox.dev",
		IsRegistration: true,
	})
	const errMsg = "no account returned in response; this is almost certainly a server error"
	if err.Error() != errMsg {
		t.Errorf("Expected error %v, got %v instead", errMsg, err)
	}
}

func TestAccountsCreate_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpectedError": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "foo", "field": "/bar"}]}`),
			err:    ErrUnexpectedError,
		},
		"missingID": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "missing", "field": "/id"}]}`),
			err:    ErrAccountRequestMissingID,
		},
		"missingProfileID": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "missing", "field": "/profileID"}]}`),
			err:    ErrAccountRequestMissingProfileID,
		},
		"invalidFormat": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "invalid_format", "field": "/"}]}`),
			err:    ErrInvalidFormatError,
		},
		"serverError": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"errors": [{"error": "act_of_god"}]}`),
			err:    ErrServerError,
		},
		"alreadyRegistered": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors":[{"error": "conflict", "field": "/id"}]}`),
			err:    ErrAccountAlreadyRegistered,
		},
		"invalidCredentials": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors":[{"error": "access_denied", "header": "Authorization"}]}`),
			err:    ErrUnauthorized,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			server := staticResponseServer(test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, AuthTokens{
				Access:  "test-access",
				Refresh: "test-refresh",
			})

			_, err := client.Accounts.Create(ctx, Account{
				ID:             "test@lockbox.dev",
				IsRegistration: true,
			})
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestAccountsGet_success(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1/"+url.PathEscape("test@lockbox.dev"))
		checkMethod(t, r, http.MethodGet)
		checkAuthorization(t, r, "Bearer test-access")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"accounts": [{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "` + timestamp + `", "lastSeenAt": "` + timestamp + `", "lastUsedAt": "` + timestamp + `"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access",
		Refresh: "test-refresh",
	})

	account, err := client.Accounts.Get(ctx, "test@lockbox.dev")
	if err != nil {
		t.Fatalf("Unexpected error retrieving account: %s", err)
	}
	if diff := cmp.Diff(Account{
		ID:             "test@lockbox.dev",
		ProfileID:      "testing123",
		IsRegistration: false,
		CreatedAt:      now,
		LastUsedAt:     now,
		LastSeenAt:     now,
	}, account); diff != "" {
		t.Errorf("Account mismatch (-wanted, +got): %s", diff)
	}
}

func TestAccountsGet_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpectedError": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "foo", "field": "/bar"}]}`),
			err:    ErrUnexpectedError,
		},
		"serverError": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"errors": [{"error": "act_of_god"}]}`),
			err:    ErrServerError,
		},
		"invalidCredentials": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors":[{"error": "access_denied", "header": "Authorization"}]}`),
			err:    ErrUnauthorized,
		},
		"accessDenied": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors":[{"error": "access_denied", "param": "id"}]}`),
			err:    ErrAccountAccessDenied,
		},
		"notFound": {
			status: http.StatusNotFound,
			body:   []byte(`{"errors":[{"error": "not_found", "param": "id"}]}`),
			err:    ErrAccountNotFound,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			server := staticResponseServer(test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, AuthTokens{
				Access:  "test-access",
				Refresh: "test-refresh",
			})

			_, err := client.Accounts.Get(ctx, "test@lockbox.dev")
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestAccountsGet_noAccounts(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access",
		Refresh: "test-refresh",
	})
	_, err := client.Accounts.Get(ctx, "test@lockbox.dev")
	const errMsg = "no account returned in response; this is almost certainly a server error"
	if err.Error() != errMsg {
		t.Errorf("Expected error %v, got %v instead", errMsg, err)
	}
}

func TestAccountsGet_missingID(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access",
		Refresh: "test-refresh",
	})
	_, err := client.Accounts.Get(ctx, "")
	if err != ErrAccountRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrAccountRequestMissingID, err)
	}
}

func TestAccountsListByProfileID_success(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1/?profileID=testing123")
		checkMethod(t, r, http.MethodGet)
		checkAuthorization(t, r, "Bearer test-access")

		w.WriteHeader(http.StatusOK)
		// TODO: more accounts in response
		w.Write([]byte(`{"accounts": [{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "` + timestamp + `", "lastSeenAt": "` + timestamp + `", "lastUsedAt": "` + timestamp + `"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access",
		Refresh: "test-refresh",
	})

	account, err := client.Accounts.ListByProfileID(ctx, "testing123")
	if err != nil {
		t.Fatalf("Unexpected error retrieving accounts: %s", err)
	}
	if diff := cmp.Diff([]Account{
		{
			ID:             "test@lockbox.dev",
			ProfileID:      "testing123",
			IsRegistration: false,
			CreatedAt:      now,
			LastUsedAt:     now,
			LastSeenAt:     now,
		},
	}, account); diff != "" {
		t.Errorf("Accounts mismatch (-wanted, +got): %s", diff)
	}
}

func TestAccountsListByProfileID_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpectedError": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "foo", "field": "/bar"}]}`),
			err:    ErrUnexpectedError,
		},
		"serverError": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"errors": [{"error": "act_of_god"}]}`),
			err:    ErrServerError,
		},
		"invalidCredentials": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors":[{"error": "access_denied", "header": "Authorization"}]}`),
			err:    ErrUnauthorized,
		},
		"accessDenied": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors":[{"error": "access_denied", "param": "profileID"}]}`),
			err:    ErrProfileAccessDenied,
		},
		"missingProfileID": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "missing", "param": "profileID"}]}`),
			err:    ErrAccountRequestMissingProfileID,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			server := staticResponseServer(test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, AuthTokens{
				Access:  "test-access",
				Refresh: "test-refresh",
			})

			_, err := client.Accounts.ListByProfileID(ctx, "testing123")
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestAccountsListByProfileID_missingProfileID(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "profileID"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access",
		Refresh: "test-refresh",
	})
	_, err := client.Accounts.ListByProfileID(ctx, "")
	if err != ErrAccountRequestMissingProfileID {
		t.Errorf("Expected error %v, got %v instead", ErrAccountRequestMissingProfileID, err)
	}
}

func TestAccountsDelete_success(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1/"+url.PathEscape("test@lockbox.dev"))
		checkMethod(t, r, http.MethodDelete)
		checkAuthorization(t, r, "Bearer test-access")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"accounts": [{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "` + timestamp + `", "lastSeenAt": "` + timestamp + `", "lastUsedAt": "` + timestamp + `"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access",
		Refresh: "test-refresh",
	})

	err := client.Accounts.Delete(ctx, "test@lockbox.dev")
	if err != nil {
		t.Fatalf("Unexpected error deleting account: %s", err)
	}
}

func TestAccountsDelete_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpectedError": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "foo", "field": "/bar"}]}`),
			err:    ErrUnexpectedError,
		},
		"serverError": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"errors": [{"error": "act_of_god"}]}`),
			err:    ErrServerError,
		},
		"invalidCredentials": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors":[{"error": "access_denied", "header": "Authorization"}]}`),
			err:    ErrUnauthorized,
		},
		"accessDenied": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors":[{"error": "access_denied", "param": "id"}]}`),
			err:    ErrAccountAccessDenied,
		},
		"notFound": {
			status: http.StatusNotFound,
			body:   []byte(`{"errors":[{"error": "not_found", "param": "id"}]}`),
			err:    ErrAccountNotFound,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			server := staticResponseServer(test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, AuthTokens{
				Access:  "test-access",
				Refresh: "test-refresh",
			})

			err := client.Accounts.Delete(ctx, "test@lockbox.dev")
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestAccountsDelete_missingID(t *testing.T) {
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access",
		Refresh: "test-refresh",
	})
	err := client.Accounts.Delete(ctx, "")
	if err != ErrAccountRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrAccountRequestMissingID, err)
	}
}
