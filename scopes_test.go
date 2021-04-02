package lockbox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-uuid"
	"yall.in"
	testinglog "yall.in/testing"
)

func TestScopesCreate_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	userID, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("Error generating user ID: %s", err)
	}
	clientID, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("Error generating client ID: %s", err)
	}

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/scopes/v1")
		checkMethod(t, r, http.MethodPost)
		checkJSONBody(t, r, fmt.Sprintf(`{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_DENY", "userExceptions": ["%s"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["%s"], "isDefault": true}`, userID, clientID))
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_DENY", "userExceptions": ["%s"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["%s"], "isDefault": true}]}`, userID, clientID)))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	result, err := client.Scopes.Create(ctx, Scope{
		ID:               "https://test.lockbox.dev/basic/scope",
		UserPolicy:       ScopesPolicyDefaultDeny,
		UserExceptions:   []string{userID},
		ClientPolicy:     ScopesPolicyDefaultAllow,
		ClientExceptions: []string{clientID},
		IsDefault:        true,
	})
	if err != nil {
		t.Fatalf("Error creating scope: %s", err)
	}
	if diff := cmp.Diff(Scope{
		ID:               "https://test.lockbox.dev/basic/scope",
		UserPolicy:       ScopesPolicyDefaultDeny,
		UserExceptions:   []string{userID},
		ClientPolicy:     ScopesPolicyDefaultAllow,
		ClientExceptions: []string{clientID},
		IsDefault:        true,
	}, result); diff != "" {
		t.Errorf("Scope mismatch (-wanted, +got): %s", diff)
	}
}

func TestScopesCreate_noScopes(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecretkey"),
	}

	server := staticResponseServer(http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	_, err := client.Scopes.Create(ctx, Scope{
		ID:           "https://test.lockbox.dev/basic/scope",
		UserPolicy:   ScopesPolicyDefaultAllow,
		ClientPolicy: ScopesPolicyDefaultAllow,
		IsDefault:    true,
	})
	const errMsg = "no scopes in the response; this is almost certainly a server error"
	if err.Error() != errMsg {
		t.Errorf("Expected error %v, got %v instead", errMsg, err)
	}
}

func TestScopesCreate_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpectedError": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "foo", "field": "/bar"}]}`),
			err:    ErrUnexpectedError,
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
		"invalidCredentials": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors":[{"error": "access_denied", "header": "Authorization"}]}`),
			err:    ErrUnauthorized,
		},
		"missingClientPolicy": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "missing", "field": "/clientPolicy"}]}`),
			err:    ErrScopeRequestMissingClientPolicy,
		},
		"invalidClientPolicy": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "invalid_value", "field": "/clientPolicy"}]}`),
			err:    ErrScopeRequestInvalidClientPolicy,
		},
		"missingUserPolicy": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "missing", "field": "/userPolicy"}]}`),
			err:    ErrScopeRequestMissingUserPolicy,
		},
		"invalidUserPolicy": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "invalid_value", "field": "/userPolicy"}]}`),
			err:    ErrScopeRequestInvalidUserPolicy,
		},
		"missingID": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "missing", "field": "/id"}]}`),
			err:    ErrScopeRequestMissingID,
		},
		"alreadyExists": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors":[{"error": "conflict", "field": "/id"}]}`),
			err:    ErrScopeAlreadyExists,
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			hmacOpts := HMACAuth{
				MaxSkew: time.Minute,
				OrgKey:  "LOCKBOXTEST",
				Key:     "testkey",
				Secret:  []byte("mysecrethmackey"),
			}

			server := staticResponseServer(test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Scopes: hmacOpts,
			})

			_, err := client.Scopes.Create(ctx, Scope{
				ID:           "https://test.lockbox.dev/basic/scope",
				UserPolicy:   ScopesPolicyDefaultAllow,
				ClientPolicy: ScopesPolicyDefaultAllow,
				IsDefault:    true,
			})

			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestScopesGet_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	userUUID, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("error generating user UUID: %s", err)
	}

	clientUUID, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("error generating client UUID: %s", err)
	}

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/scopes/v1/"+url.PathEscape("https://test.lockbox.dev/basic/scope"))
		checkMethod(t, r, http.MethodGet)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_ALLOW", "userExceptions": ["` + userUUID + `"], "clientPolicy": "DEFAULT_DENY", "clientExceptions": ["` + clientUUID + `"], "isDefault": true}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	apiClient, err := client.Scopes.Get(ctx, "https://test.lockbox.dev/basic/scope")
	if err != nil {
		t.Fatalf("Unexpected error retrieving client: %s", err)
	}
	if diff := cmp.Diff(Scope{
		ID:               "https://test.lockbox.dev/basic/scope",
		UserPolicy:       ScopesPolicyDefaultAllow,
		UserExceptions:   []string{userUUID},
		ClientPolicy:     ScopesPolicyDefaultDeny,
		ClientExceptions: []string{clientUUID},
		IsDefault:        true,
	}, apiClient); diff != "" {
		t.Errorf("Client mismatch (-wanted, +got): %s", diff)
	}
}

func TestScopesGet_errors(t *testing.T) {
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
		"notFound": {
			status: http.StatusNotFound,
			body:   []byte(`{"errors":[{"error": "not_found", "param": "id"}]}`),
			err:    ErrScopeNotFound,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			hmacOpts := HMACAuth{
				MaxSkew: time.Minute,
				OrgKey:  "LOCKBOXTEST",
				Key:     "testkey",
				Secret:  []byte("mysecrethmackey"),
			}

			server := staticResponseServer(test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Scopes: hmacOpts,
			})

			_, err := client.Scopes.Get(ctx, "https://test.lockbox.dev/scopes/basic")
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestScopesGet_noScopes(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(http.StatusOK, []byte(`{}`))
	defer server.Close()

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})
	_, err := client.Scopes.Get(ctx, "https://test.lockbox.dev/scopes/basic")
	const errMsg = "no scopes in the response; this is almost certainly a server error"
	if err.Error() != errMsg {
		t.Errorf("Expected error %v, got %v instead", errMsg, err)
	}
}

func TestScopesGet_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})
	_, err := client.Scopes.Get(ctx, "")
	if err != ErrScopeRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrScopeRequestMissingID, err)
	}
}

func TestScopesDelete_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	userUUID, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("error generating user UUID: %s", err)
	}

	clientUUID, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("error generating client UUID: %s", err)
	}

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/scopes/v1/"+url.PathEscape("https://test.lockbox.dev/basic/scope"))
		checkMethod(t, r, http.MethodDelete)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_ALLOW", "userExceptions": ["` + userUUID + `"], "clientPolicy": "DEFAULT_DENY", "clientExceptions": ["` + clientUUID + `"], "isDefault": true}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	err = client.Scopes.Delete(ctx, "https://test.lockbox.dev/basic/scope")
	if err != nil {
		t.Fatalf("Unexpected error retrieving client: %s", err)
	}
}

func TestScopesDelete_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpectedError": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "foo", "field": "/bar"}]}`),
			err:    ErrUnexpectedError,
		},
		"serverError": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"errors":[{"error": "act_of_god"}]}`),
			err:    ErrServerError,
		},
		"invalidCredentials": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors": [{"error": "access_denied", "header": "Authorization"}]}`),
			err:    ErrUnauthorized,
		},
		"notFound": {
			status: http.StatusNotFound,
			body:   []byte(`{"errors":[{"error": "not_found", "param": "id"}]}`),
			err:    ErrScopeNotFound,
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

			hmacOpts := HMACAuth{
				MaxSkew: time.Minute,
				OrgKey:  "LOCKBOXTEST",
				Key:     "testkey",
				Secret:  []byte("mysecrethmackey"),
			}

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Scopes: hmacOpts,
			})

			id, err := uuid.GenerateUUID()
			if err != nil {
				t.Errorf("error generating UUID: %s", err)
				return
			}

			err = client.Scopes.Delete(ctx, id)
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestScopesDelete_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	err := client.Scopes.Delete(ctx, "")
	if err != ErrScopeRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrScopeRequestMissingID, err)
	}
}
