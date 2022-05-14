package lockbox

import (
	"context"
	"errors"
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
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1")
		checkMethod(t, r, http.MethodPost)
		checkJSONBody(t, r, `{"id": "test@lockbox.dev", "isRegistration": true, "createdAt": "0001-01-01T00:00:00Z", "lastSeenAt": "0001-01-01T00:00:00Z", "lastUsedAt": "0001-01-01T00:00:00Z"}`)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"accounts": [{"id": "test@lockbox.dev", "isRegistration": true, "createdAt": "`+timestamp+`", "lastSeenAt": "`+timestamp+`", "lastUsedAt": "`+timestamp+`", "profileID": "b9d7ed67-330b-481d-ad50-2208fe30b947"}]}`))
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
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1")
		checkMethod(t, r, http.MethodPost)
		checkBearerToken(t, r, "test-access-add")
		checkJSONBody(t, r, `{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "0001-01-01T00:00:00Z", "lastSeenAt": "0001-01-01T00:00:00Z", "lastUsedAt": "0001-01-01T00:00:00Z"}`)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"accounts": [{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "`+timestamp+`", "lastSeenAt": "`+timestamp+`", "lastUsedAt": "`+timestamp+`"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access-add",
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
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL)
	_, err := client.Accounts.Create(ctx, Account{
		ID:             "test@lockbox.dev",
		IsRegistration: true,
	})
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Errorf("Expected error %v, got %v instead", ErrUnexpectedResponse, err)
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

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, AuthTokens{
				Access:  "test-access-add",
				Refresh: "test-refresh",
			})

			_, err := client.Accounts.Create(ctx, Account{
				ID:             "test@lockbox.dev",
				IsRegistration: true,
			})
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestAccountsGet_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1/"+url.PathEscape("test@lockbox.dev"))
		checkMethod(t, r, http.MethodGet)
		checkBearerToken(t, r, "test-access-get")

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"accounts": [{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "`+timestamp+`", "lastSeenAt": "`+timestamp+`", "lastUsedAt": "`+timestamp+`"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access-get",
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

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, AuthTokens{
				Access:  "test-access-get",
				Refresh: "test-refresh",
			})

			_, err := client.Accounts.Get(ctx, "test@lockbox.dev")
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestAccountsGet_noAccounts(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access-get",
		Refresh: "test-refresh",
	})
	_, err := client.Accounts.Get(ctx, "test@lockbox.dev")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Errorf("Expected error %v, got %v instead", ErrUnexpectedResponse, err)
	}
}

func TestAccountsGet_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access-get",
		Refresh: "test-refresh",
	})
	_, err := client.Accounts.Get(ctx, "")
	if !errors.Is(err, ErrAccountRequestMissingID) {
		t.Errorf("Expected error %v, got %v instead", ErrAccountRequestMissingID, err)
	}
}

func TestAccountsListByProfileID_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1/?profileID=testing123")
		checkMethod(t, r, http.MethodGet)
		checkBearerToken(t, r, "test-access-by-profile")

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"accounts": [`))
		mustWrite(t, w, []byte(`{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "`+now.Format(time.RFC3339)+`", "lastSeenAt": "`+now.Format(time.RFC3339)+`", "lastUsedAt": "`+now.Format(time.RFC3339)+`"},`))
		mustWrite(t, w, []byte(`{"id": "test2@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "`+now.Add(-1*time.Second).Format(time.RFC3339)+`", "lastSeenAt": "`+now.Add(-1*time.Second).Format(time.RFC3339)+`", "lastUsedAt": "`+now.Add(-1*time.Second).Format(time.RFC3339)+`"},`))
		mustWrite(t, w, []byte(`{"id": "test3@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "`+now.Add(-4*time.Second).Format(time.RFC3339)+`", "lastSeenAt": "`+now.Add(-3*time.Second).Format(time.RFC3339)+`", "lastUsedAt": "`+now.Add(-2*time.Second).Format(time.RFC3339)+`"},`))
		mustWrite(t, w, []byte(`{"id": "test4@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "`+now.Add(-7*time.Second).Format(time.RFC3339)+`", "lastSeenAt": "`+now.Add(-6*time.Second).Format(time.RFC3339)+`", "lastUsedAt": "`+now.Add(-5*time.Second).Format(time.RFC3339)+`"},`))
		mustWrite(t, w, []byte(`{"id": "test5@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "`+now.Add(-10*time.Second).Format(time.RFC3339)+`", "lastSeenAt": "`+now.Add(-9*time.Second).Format(time.RFC3339)+`", "lastUsedAt": "`+now.Add(-8*time.Second).Format(time.RFC3339)+`"}`))
		mustWrite(t, w, []byte(`]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access-by-profile",
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
		{
			ID:             "test2@lockbox.dev",
			ProfileID:      "testing123",
			IsRegistration: false,
			CreatedAt:      now.Add(-1 * time.Second),
			LastUsedAt:     now.Add(-1 * time.Second),
			LastSeenAt:     now.Add(-1 * time.Second),
		},
		{
			ID:             "test3@lockbox.dev",
			ProfileID:      "testing123",
			IsRegistration: false,
			CreatedAt:      now.Add(-4 * time.Second),
			LastUsedAt:     now.Add(-2 * time.Second),
			LastSeenAt:     now.Add(-3 * time.Second),
		},
		{
			ID:             "test4@lockbox.dev",
			ProfileID:      "testing123",
			IsRegistration: false,
			CreatedAt:      now.Add(-7 * time.Second),
			LastUsedAt:     now.Add(-5 * time.Second),
			LastSeenAt:     now.Add(-6 * time.Second),
		},
		{
			ID:             "test5@lockbox.dev",
			ProfileID:      "testing123",
			IsRegistration: false,
			CreatedAt:      now.Add(-10 * time.Second),
			LastUsedAt:     now.Add(-8 * time.Second),
			LastSeenAt:     now.Add(-9 * time.Second),
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

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, AuthTokens{
				Access:  "test-access-by-profile",
				Refresh: "test-refresh",
			})

			_, err := client.Accounts.ListByProfileID(ctx, "testing123")
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestAccountsListByProfileID_missingProfileID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "profileID"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access-by-profile",
		Refresh: "test-refresh",
	})
	_, err := client.Accounts.ListByProfileID(ctx, "")
	if !errors.Is(err, ErrAccountRequestMissingProfileID) {
		t.Errorf("Expected error %v, got %v instead", ErrAccountRequestMissingProfileID, err)
	}
}

func TestAccountsDelete_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/accounts/v1/"+url.PathEscape("test@lockbox.dev"))
		checkMethod(t, r, http.MethodDelete)
		checkBearerToken(t, r, "test-access-delete")

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"accounts": [{"id": "test@lockbox.dev", "isRegistration": false, "profileID": "testing123", "createdAt": "`+timestamp+`", "lastSeenAt": "`+timestamp+`", "lastUsedAt": "`+timestamp+`"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access-delete",
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

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, AuthTokens{
				Access:  "test-access-delete",
				Refresh: "test-refresh",
			})

			err := client.Accounts.Delete(ctx, "test@lockbox.dev")
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestAccountsDelete_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, AuthTokens{
		Access:  "test-access-delete",
		Refresh: "test-refresh",
	})
	err := client.Accounts.Delete(ctx, "")
	if !errors.Is(err, ErrAccountRequestMissingID) {
		t.Errorf("Expected error %v, got %v instead", ErrAccountRequestMissingID, err)
	}
}
