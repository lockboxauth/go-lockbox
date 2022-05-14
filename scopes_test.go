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
	"yall.in"
	testinglog "yall.in/testing"
)

func TestScopesCreate_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	userID := uuidOrFail(t)
	clientID := uuidOrFail(t)

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
		mustWrite(t, w, []byte(fmt.Sprintf(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_DENY", "userExceptions": ["%s"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["%s"], "isDefault": true}]}`, userID, clientID)))
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

	server := staticResponseServer(t, http.StatusOK, []byte(`{}`))
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
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Errorf("Expected error %v, got %v instead", ErrUnexpectedResponse, err)
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

			server := staticResponseServer(t, test.status, test.body)
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

	userUUID := uuidOrFail(t)
	clientUUID := uuidOrFail(t)

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
		mustWrite(t, w, []byte(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_ALLOW", "userExceptions": ["`+userUUID+`"], "clientPolicy": "DEFAULT_DENY", "clientExceptions": ["`+clientUUID+`"], "isDefault": true}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	scope, err := client.Scopes.Get(ctx, "https://test.lockbox.dev/basic/scope")
	if err != nil {
		t.Fatalf("Unexpected error retrieving scope: %s", err)
	}
	if diff := cmp.Diff(Scope{
		ID:               "https://test.lockbox.dev/basic/scope",
		UserPolicy:       ScopesPolicyDefaultAllow,
		UserExceptions:   []string{userUUID},
		ClientPolicy:     ScopesPolicyDefaultDeny,
		ClientExceptions: []string{clientUUID},
		IsDefault:        true,
	}, scope); diff != "" {
		t.Errorf("Scope mismatch (-wanted, +got): %s", diff)
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

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Scopes: hmacOpts,
			})

			_, err := client.Scopes.Get(ctx, "https://test.lockbox.dev/scopes/basic")
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestScopesGet_noScopes(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusOK, []byte(`{}`))
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
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Errorf("Expected error %v, got %v instead", ErrUnexpectedResponse, err)
	}
}

func TestScopesGet_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
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
	if !errors.Is(err, ErrScopeRequestMissingID) {
		t.Errorf("Expected error %v, got %v instead", ErrScopeRequestMissingID, err)
	}
}

func TestScopesUpdate_full(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	userID := uuidOrFail(t)
	clientID := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/scopes/v1/"+url.PathEscape("https://test.lockbox.dev/basic/scope"))
		checkMethod(t, r, http.MethodPatch)
		checkJSONBody(t, r, fmt.Sprintf(`{"userPolicy": "DEFAULT_DENY", "userExceptions": ["%s"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["%s"], "isDefault": true}`, userID, clientID))
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(fmt.Sprintf(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_DENY", "userExceptions": ["%s"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["%s"], "isDefault": true}]}`, userID, clientID)))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	result, err := client.Scopes.Update(ctx, "https://test.lockbox.dev/basic/scope", ScopeChange{}.
		SetUserPolicy(ScopesPolicyDefaultDeny).
		SetUserExceptions([]string{userID}).
		SetClientPolicy(ScopesPolicyDefaultAllow).
		SetClientExceptions([]string{clientID}).
		SetIsDefault(true))
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

func TestScopesUpdate_zeroValues(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/scopes/v1/"+url.PathEscape("https://test.lockbox.dev/basic/scope"))
		checkMethod(t, r, http.MethodPatch)
		checkJSONBody(t, r, `{"userPolicy": "DEFAULT_DENY", "userExceptions": [], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": [], "isDefault": false}`)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_DENY", "userExceptions": [], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": [], "isDefault": false}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	result, err := client.Scopes.Update(ctx, "https://test.lockbox.dev/basic/scope", ScopeChange{}.
		SetUserPolicy(ScopesPolicyDefaultDeny).
		SetUserExceptions([]string{}).
		SetClientPolicy(ScopesPolicyDefaultAllow).
		SetClientExceptions([]string{}).
		SetIsDefault(false))
	if err != nil {
		t.Fatalf("Error creating scope: %s", err)
	}
	if diff := cmp.Diff(Scope{
		ID:               "https://test.lockbox.dev/basic/scope",
		UserPolicy:       ScopesPolicyDefaultDeny,
		UserExceptions:   []string{},
		ClientPolicy:     ScopesPolicyDefaultAllow,
		ClientExceptions: []string{},
		IsDefault:        false,
	}, result); diff != "" {
		t.Errorf("Scope mismatch (-wanted, +got): %s", diff)
	}
}

func TestScopesUpdate_defaultOnly(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	userID := uuidOrFail(t)
	clientID := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/scopes/v1/"+url.PathEscape("https://test.lockbox.dev/basic/scope"))
		checkMethod(t, r, http.MethodPatch)
		checkJSONBody(t, r, `{"isDefault": false}`)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(fmt.Sprintf(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_DENY", "userExceptions": ["%s"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["%s"], "isDefault": false}]}`, userID, clientID)))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	result, err := client.Scopes.Update(ctx, "https://test.lockbox.dev/basic/scope", ScopeChange{}.
		SetIsDefault(false))
	if err != nil {
		t.Fatalf("Error creating scope: %s", err)
	}
	if diff := cmp.Diff(Scope{
		ID:               "https://test.lockbox.dev/basic/scope",
		UserPolicy:       ScopesPolicyDefaultDeny,
		UserExceptions:   []string{userID},
		ClientPolicy:     ScopesPolicyDefaultAllow,
		ClientExceptions: []string{clientID},
		IsDefault:        false,
	}, result); diff != "" {
		t.Errorf("Scope mismatch (-wanted, +got): %s", diff)
	}
}

func TestScopesUpdate_clientPolicyOnly(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/scopes/v1/"+url.PathEscape("https://test.lockbox.dev/basic/scope"))
		checkMethod(t, r, http.MethodPatch)
		checkJSONBody(t, r, `{"clientPolicy": "DEFAULT_DENY"}`)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_DENY", "userExceptions": [], "clientPolicy": "DEFAULT_DENY", "clientExceptions": [], "isDefault": false}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	result, err := client.Scopes.Update(ctx, "https://test.lockbox.dev/basic/scope", ScopeChange{}.
		SetClientPolicy(ScopesPolicyDefaultDeny))
	if err != nil {
		t.Fatalf("Error creating scope: %s", err)
	}
	if diff := cmp.Diff(Scope{
		ID:               "https://test.lockbox.dev/basic/scope",
		UserPolicy:       ScopesPolicyDefaultDeny,
		UserExceptions:   []string{},
		ClientPolicy:     ScopesPolicyDefaultDeny,
		ClientExceptions: []string{},
		IsDefault:        false,
	}, result); diff != "" {
		t.Errorf("Scope mismatch (-wanted, +got): %s", diff)
	}
}

func TestScopesUpdate_noScopes(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecretkey"),
	}

	server := staticResponseServer(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	_, err := client.Scopes.Update(ctx, "https://test.lockbox.dev/basic/scope", ScopeChange{}.
		SetIsDefault(true))
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Errorf("Expected error %v, got %v instead", ErrUnexpectedResponse, err)
	}
}

func TestScopesUpdate_errors(t *testing.T) {
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
		"invalidClientPolicy": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "invalid_value", "field": "/clientPolicy"}]}`),
			err:    ErrScopeRequestInvalidClientPolicy,
		},
		"invalidUserPolicy": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "invalid_value", "field": "/userPolicy"}]}`),
			err:    ErrScopeRequestInvalidUserPolicy,
		},
		"notFound": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "not_found", "param": "id"}]}`),
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

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Scopes: hmacOpts,
			})

			_, err := client.Scopes.Update(ctx, "https://test.lockbox.dev/basic/scope", ScopeChange{}.
				SetIsDefault(true))

			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestScopesUpdate_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
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

	_, err := client.Scopes.Update(ctx, "", ScopeChange{}.SetIsDefault(true))
	if !errors.Is(err, ErrScopeRequestMissingID) {
		t.Errorf("Expected error %v, got %v instead", ErrScopeRequestMissingID, err)
	}
}

func TestScopesDelete_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	userUUID := uuidOrFail(t)
	clientUUID := uuidOrFail(t)

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
		mustWrite(t, w, []byte(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_ALLOW", "userExceptions": ["`+userUUID+`"], "clientPolicy": "DEFAULT_DENY", "clientExceptions": ["`+clientUUID+`"], "isDefault": true}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	err := client.Scopes.Delete(ctx, "https://test.lockbox.dev/basic/scope")
	if err != nil {
		t.Fatalf("Unexpected error deleting scope: %s", err)
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

			server := staticResponseServer(t, test.status, test.body)
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

			err := client.Scopes.Delete(ctx, uuidOrFail(t))
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestScopesDelete_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
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
	if !errors.Is(err, ErrScopeRequestMissingID) {
		t.Errorf("Expected error %v, got %v instead", ErrScopeRequestMissingID, err)
	}
}

func TestScopesListDefault_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	userUUID := uuidOrFail(t)
	clientUUID := uuidOrFail(t)
	user2UUID := uuidOrFail(t)
	client2UUID := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/scopes/v1/?default=true")
		checkMethod(t, r, http.MethodGet)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_ALLOW", "userExceptions": ["`+userUUID+`"], "clientPolicy": "DEFAULT_DENY", "clientExceptions": ["`+clientUUID+`"], "isDefault": true}, {"id": "https://test.lockbox.dev/basic/scope2", "userPolicy": "DEFAULT_DENY", "userExceptions": ["`+user2UUID+`"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["`+client2UUID+`"], "isDefault": true}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Scopes: hmacOpts,
	})

	scopes, err := client.Scopes.ListDefault(ctx)
	if err != nil {
		t.Fatalf("Unexpected error listing default scopes: %s", err)
	}
	if diff := cmp.Diff([]Scope{
		{
			ID:               "https://test.lockbox.dev/basic/scope",
			UserPolicy:       ScopesPolicyDefaultAllow,
			UserExceptions:   []string{userUUID},
			ClientPolicy:     ScopesPolicyDefaultDeny,
			ClientExceptions: []string{clientUUID},
			IsDefault:        true,
		},
		{
			ID:               "https://test.lockbox.dev/basic/scope2",
			UserPolicy:       ScopesPolicyDefaultDeny,
			UserExceptions:   []string{user2UUID},
			ClientPolicy:     ScopesPolicyDefaultAllow,
			ClientExceptions: []string{client2UUID},
			IsDefault:        true,
		},
	}, scopes); diff != "" {
		t.Errorf("Scopes mismatch (-wanted, +got): %s", diff)
	}
}

func TestScopesListDefault_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"unexpected-error": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "foo", "field": "/bar"}]}`),
			err:    ErrUnexpectedError,
		},
		"server-error": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"errors": [{"error": "act_of_god"}]}`),
			err:    ErrServerError,
		},
		"invalid-credentials": {
			status: http.StatusUnauthorized,
			body:   []byte(`{"errors":[{"error": "access_denied", "header": "Authorization"}]}`),
			err:    ErrUnauthorized,
		},
		"missing-default-value": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "missing", "param": "default"}]}`),
			err:    ErrInvalidRequestError,
		},
		"invalid-default-value": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "invalid_value", "param": "default"}]}`),
			err:    ErrInvalidRequestError,
		},
		"default-and-ids-conflict": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "conflict", "param": "default,id"}]}`),
			err:    ErrInvalidRequestError,
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

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Scopes: hmacOpts,
			})

			_, err := client.Scopes.ListDefault(ctx)
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestScopesGetByIDs_success(t *testing.T) {
	t.Parallel()
	userUUID := uuidOrFail(t)
	clientUUID := uuidOrFail(t)
	user2UUID := uuidOrFail(t)
	client2UUID := uuidOrFail(t)
	user3UUID := uuidOrFail(t)
	client3UUID := uuidOrFail(t)

	type testCase struct {
		ids            []string
		response       string
		expectedURL    string
		expectedScopes map[string]Scope
	}

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	tests := map[string]testCase{
		"single": {
			ids:         []string{"https://test.lockbox.dev/basic/scope"},
			response:    `{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_ALLOW", "userExceptions": ["` + userUUID + `"], "clientPolicy": "DEFAULT_DENY", "clientExceptions": ["` + clientUUID + `"], "isDefault": true}]}`,
			expectedURL: "/scopes/v1/?id=https%3A%2F%2Ftest.lockbox.dev%2Fbasic%2Fscope",
			expectedScopes: map[string]Scope{
				"https://test.lockbox.dev/basic/scope": {
					ID:               "https://test.lockbox.dev/basic/scope",
					UserPolicy:       ScopesPolicyDefaultAllow,
					UserExceptions:   []string{userUUID},
					ClientPolicy:     ScopesPolicyDefaultDeny,
					ClientExceptions: []string{clientUUID},
					IsDefault:        true,
				},
			},
		},
		"two": {
			ids:         []string{"https://test.lockbox.dev/basic/scope", "https://test.lockbox.dev/basic/scope2"},
			response:    `{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_ALLOW", "userExceptions": ["` + userUUID + `"], "clientPolicy": "DEFAULT_DENY", "clientExceptions": ["` + clientUUID + `"], "isDefault": true},{"id": "https://test.lockbox.dev/basic/scope2", "userPolicy": "DEFAULT_DENY", "userExceptions": ["` + user2UUID + `"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["` + client2UUID + `"], "isDefault": true}]}`,
			expectedURL: "/scopes/v1/?id=https%3A%2F%2Ftest.lockbox.dev%2Fbasic%2Fscope&id=https%3A%2F%2Ftest.lockbox.dev%2Fbasic%2Fscope2",
			expectedScopes: map[string]Scope{
				"https://test.lockbox.dev/basic/scope": {
					ID:               "https://test.lockbox.dev/basic/scope",
					UserPolicy:       ScopesPolicyDefaultAllow,
					UserExceptions:   []string{userUUID},
					ClientPolicy:     ScopesPolicyDefaultDeny,
					ClientExceptions: []string{clientUUID},
					IsDefault:        true,
				},
				"https://test.lockbox.dev/basic/scope2": {
					ID:               "https://test.lockbox.dev/basic/scope2",
					UserPolicy:       ScopesPolicyDefaultDeny,
					UserExceptions:   []string{user2UUID},
					ClientPolicy:     ScopesPolicyDefaultAllow,
					ClientExceptions: []string{client2UUID},
					IsDefault:        true,
				},
			},
		},
		"three": {
			ids:         []string{"https://test.lockbox.dev/basic/scope", "https://test.lockbox.dev/basic/scope2", "https://test.lockbox.dev/basic/scope3"},
			response:    `{"scopes": [{"id": "https://test.lockbox.dev/basic/scope", "userPolicy": "DEFAULT_ALLOW", "userExceptions": ["` + userUUID + `"], "clientPolicy": "DEFAULT_DENY", "clientExceptions": ["` + clientUUID + `"], "isDefault": true},{"id": "https://test.lockbox.dev/basic/scope2", "userPolicy": "DEFAULT_DENY", "userExceptions": ["` + user2UUID + `"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["` + client2UUID + `"], "isDefault": true},{"id": "https://test.lockbox.dev/basic/scope3", "userPolicy": "DEFAULT_ALLOW", "userExceptions": ["` + userUUID + `","` + user2UUID + `","` + user3UUID + `"], "clientPolicy": "DEFAULT_ALLOW", "clientExceptions": ["` + clientUUID + `","` + client2UUID + `","` + client3UUID + `"], "isDefault": false}]}`,
			expectedURL: "/scopes/v1/?id=https%3A%2F%2Ftest.lockbox.dev%2Fbasic%2Fscope&id=https%3A%2F%2Ftest.lockbox.dev%2Fbasic%2Fscope2&id=https%3A%2F%2Ftest.lockbox.dev%2Fbasic%2Fscope3",
			expectedScopes: map[string]Scope{
				"https://test.lockbox.dev/basic/scope": {
					ID:               "https://test.lockbox.dev/basic/scope",
					UserPolicy:       ScopesPolicyDefaultAllow,
					UserExceptions:   []string{userUUID},
					ClientPolicy:     ScopesPolicyDefaultDeny,
					ClientExceptions: []string{clientUUID},
					IsDefault:        true,
				},
				"https://test.lockbox.dev/basic/scope2": {
					ID:               "https://test.lockbox.dev/basic/scope2",
					UserPolicy:       ScopesPolicyDefaultDeny,
					UserExceptions:   []string{user2UUID},
					ClientPolicy:     ScopesPolicyDefaultAllow,
					ClientExceptions: []string{client2UUID},
					IsDefault:        true,
				},
				"https://test.lockbox.dev/basic/scope3": {
					ID:               "https://test.lockbox.dev/basic/scope3",
					UserPolicy:       ScopesPolicyDefaultAllow,
					UserExceptions:   []string{userUUID, user2UUID, user3UUID},
					ClientPolicy:     ScopesPolicyDefaultAllow,
					ClientExceptions: []string{clientUUID, client2UUID, client3UUID},
					IsDefault:        false,
				},
			},
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				checkURL(t, r, test.expectedURL)
				checkMethod(t, r, http.MethodGet)
				checkHMACAuthorization(t, r, hmacOpts)

				w.WriteHeader(http.StatusOK)
				mustWrite(t, w, []byte(test.response))
			}))
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Scopes: hmacOpts,
			})

			scopes, err := client.Scopes.GetByIDs(ctx, test.ids)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if diff := cmp.Diff(test.expectedScopes, scopes); diff != "" {
				t.Errorf("Scopes mismatch (-wanted, +got): %s", diff)
			}
		})
	}
}

func TestScopesGetByIDs_errors(t *testing.T) {
	t.Parallel()
	tests := map[string]errorTest{
		"default-and-ids-conflict": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "conflict", "param": "default,id"}]}`),
			err:    ErrInvalidRequestError,
		},
		"no-ids": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "missing", "param": "default"}]}`),
			err:    ErrScopeRequestMissingID,
		},
		"unexpected-error": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors": [{"error": "foo", "field": "/bar"}]}`),
			err:    ErrUnexpectedError,
		},
		"server-error": {
			status: http.StatusInternalServerError,
			body:   []byte(`{"errors": [{"error": "act_of_god"}]}`),
			err:    ErrServerError,
		},
		"invalid-credentials": {
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

			hmacOpts := HMACAuth{
				MaxSkew: time.Minute,
				OrgKey:  "LOCKBOXTEST",
				Key:     "testkey",
				Secret:  []byte("mysecrethmackey"),
			}

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Scopes: hmacOpts,
			})

			_, err := client.Scopes.GetByIDs(ctx, []string{"https://test.lockbox.dev/scopes/basic"})
			if !errors.Is(err, test.err) {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestScopesGetByIDs_missingIDs(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "default"}]}`))
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

	_, err := client.Scopes.GetByIDs(ctx, nil)
	if !errors.Is(err, ErrScopeRequestMissingID) {
		t.Errorf("Expected error %v, got %v instead", ErrScopeRequestMissingID, err)
	}
}
