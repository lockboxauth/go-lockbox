package lockbox

import (
	"context"
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

func TestClientsCreate_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	createdAt := time.Now().Round(time.Second)
	createdAtStamp := createdAt.Format(time.RFC3339)
	createdBy := "testuser"
	createdByIP := "1.1.1.1"
	secret := "thisisverysecret"

	id := uuidOrFail(t)
	nameUUID := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/clients/v1")
		checkMethod(t, r, http.MethodPost)
		checkJSONBody(t, r, fmt.Sprintf(`{"client": {"name": %q, "confidential": true, "createdAt": "0001-01-01T00:00:00Z"}}`, nameUUID))
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(fmt.Sprintf(`{"clients": [{"id": %q, "name": %q, "confidential": true, "createdAt": %q, "createdBy": %q, "createdByIP": %q, "secret": %q}]}`, id, nameUUID, createdAtStamp, createdBy, createdByIP, secret)))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})

	result, err := client.Clients.Create(ctx, APIClient{
		Name:         nameUUID,
		Confidential: true,
	})
	if err != nil {
		t.Fatalf("Error creating client: %s", err)
	}
	if diff := cmp.Diff(APIClient{
		ID:           id,
		Name:         nameUUID,
		Confidential: true,
		CreatedAt:    createdAt,
		CreatedBy:    createdBy,
		CreatedByIP:  createdByIP,
		Secret:       secret,
	}, result); diff != "" {
		t.Errorf("Client mismatch (-wanted, +got): %s", diff)
	}
}

func TestClientsCreate_noClients(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	nameUUID := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := staticResponseServer(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})

	_, err := client.Clients.Create(ctx, APIClient{
		Name:         nameUUID,
		Confidential: true,
	})

	const errMsg = "no client found in response; this is almost certainly a server error"
	if err.Error() != errMsg {
		t.Errorf("Expected error %v, got %v instead", errMsg, err)
	}
}

func TestClientsCreate_errors(t *testing.T) {
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
		"alreadyExists": {
			status: http.StatusBadRequest,
			body:   []byte(`{"errors":[{"error": "conflict", "field": "/client/id"}]}`),
			err:    ErrClientAlreadyExists,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			nameUUID := uuidOrFail(t)

			hmacOpts := HMACAuth{
				MaxSkew: time.Minute,
				OrgKey:  "LOCKBOXTEST",
				Key:     "testkey",
				Secret:  []byte("mysecrethmackey"),
			}

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Clients: hmacOpts,
			})

			_, err := client.Clients.Create(ctx, APIClient{
				Name:         nameUUID,
				Confidential: true,
			})

			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestClientsGet_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	id := uuidOrFail(t)
	createdByID := uuidOrFail(t)
	nameUUID := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/clients/v1/"+url.PathEscape(id))
		checkMethod(t, r, http.MethodGet)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"clients": [{"id": "`+id+`", "name": "Test Client `+nameUUID+`", "confidential": true, "createdAt": "`+timestamp+`", "createdBy": "`+createdByID+`", "createdByIP": "127.0.0.1", "secret": "my very secret client secret"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})

	apiClient, err := client.Clients.Get(ctx, id)
	if err != nil {
		t.Fatalf("Unexpected error retrieving client: %s", err)
	}
	if diff := cmp.Diff(APIClient{
		ID:           id,
		Name:         "Test Client " + nameUUID,
		Confidential: true,
		CreatedAt:    now,
		CreatedBy:    createdByID,
		CreatedByIP:  "127.0.0.1",
		Secret:       "my very secret client secret",
	}, apiClient); diff != "" {
		t.Errorf("Client mismatch (-wanted, +got): %s", diff)
	}
}

func TestClientsGet_errors(t *testing.T) {
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
			err:    ErrClientNotFound,
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

			id := uuidOrFail(t)

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Clients: hmacOpts,
			})

			_, err := client.Clients.Get(ctx, id)
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestClientsGet_noClients(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	id := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})
	_, err := client.Clients.Get(ctx, id)
	const errMsg = "no client found in response; this is almost certainly a server error"
	if err.Error() != errMsg {
		t.Errorf("Expected error %v, got %v instead", errMsg, err)
	}
}

func TestClientsGet_missingID(t *testing.T) {
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
		Clients: hmacOpts,
	})
	_, err := client.Clients.Get(ctx, "")
	if err != ErrClientRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrClientRequestMissingID, err)
	}
}

func TestClientsDelete_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	id := uuidOrFail(t)
	nameUUID := uuidOrFail(t)
	createdByID := uuidOrFail(t)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/clients/v1/"+url.PathEscape(id))
		checkMethod(t, r, http.MethodDelete)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		// TODO: add redirect URIs, for completeness
		mustWrite(t, w, []byte(`{"clients": [{"id": "`+id+`", "name": "Test Client `+nameUUID+`", "confidential": true, "createdAt": "`+timestamp+`", "createdBy": "`+createdByID+`", "createdByIP": "127.0.0.1", "secret": "my very secret client secret"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})
	err := client.Clients.Delete(ctx, id)
	if err != nil {
		t.Fatalf("Unexpected error deleting client: %s", err)
	}
}

func TestClientsDelete_errors(t *testing.T) {
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
			err:    ErrClientNotFound,
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
				Clients: hmacOpts,
			})

			id := uuidOrFail(t)

			err := client.Clients.Delete(ctx, id)
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestClientsDelete_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: HMACAuth{
			MaxSkew: time.Minute,
			OrgKey:  "LOCKBOXTEST",
			Key:     "testkey",
			Secret:  []byte("mysecrethmackey"),
		},
	})

	err := client.Clients.Delete(ctx, "")
	if err != ErrClientRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrClientRequestMissingID, err)
	}
}

func TestClientsResetSecret_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	id := uuidOrFail(t)
	nameUUID := uuidOrFail(t)
	createdByID := uuidOrFail(t)

	now := time.Now().Round(time.Second)
	timestamp := now.Format(time.RFC3339)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/clients/v1/"+url.PathEscape(id)+"/secret")
		checkMethod(t, r, http.MethodPost)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"clients": [{"id": "`+id+`", "name": "Test Client `+nameUUID+`", "confidential": true, "createdAt": "`+timestamp+`", "createdBy": "`+createdByID+`", "createdByIP": "127.0.0.1", "secret": "my very secret new client secret"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})
	result, err := client.Clients.ResetSecret(ctx, id)
	if err != nil {
		t.Fatalf("Unexpected error deleting client: %s", err)
	}
	if diff := cmp.Diff(APIClient{
		ID:           id,
		Name:         "Test Client " + nameUUID,
		Confidential: true,
		CreatedAt:    now,
		CreatedBy:    createdByID,
		CreatedByIP:  "127.0.0.1",
		Secret:       "my very secret new client secret",
	}, result); diff != "" {
		t.Errorf("Client mismatch (-wanted, +got): %s", diff)
	}
}

func TestClientsResetSecret_errors(t *testing.T) {
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
			err:    ErrClientNotFound,
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
				Clients: hmacOpts,
			})

			id := uuidOrFail(t)

			_, err := client.Clients.ResetSecret(ctx, id)
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestClientsResetSecret_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: HMACAuth{
			MaxSkew: time.Minute,
			OrgKey:  "LOCKBOXTEST",
			Key:     "testkey",
			Secret:  []byte("mysecrethmackey"),
		},
	})

	_, err := client.Clients.ResetSecret(ctx, "")
	if err != ErrClientRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrClientRequestMissingID, err)
	}
}

func TestClientsResetSecret_noClients(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	id := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})
	_, err := client.Clients.ResetSecret(ctx, id)
	const errMsg = "no client found in response; this is almost certainly a server error"
	if err.Error() != errMsg {
		t.Errorf("Expected error %v, got %v instead", errMsg, err)
	}
}

func TestRedirectURIsCreate_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	createdAt := time.Now().Round(time.Second)
	createdAtStamp := createdAt.Format(time.RFC3339)
	createdBy := "testuser"

	id := uuidOrFail(t)
	id2 := uuidOrFail(t)
	clientID := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/clients/v1/"+url.PathEscape(clientID)+"/redirectURIs")
		checkMethod(t, r, http.MethodPost)
		checkJSONBody(t, r, `{"redirectURIs":[{"URI": "https://lockbox.dev/", "isBaseURI": true, "createdAt": "0001-01-01T00:00:00Z"}, {"URI": "https://impractical.co/auth", "isBaseURI": false, "createdAt": "0001-01-01T00:00:00Z"}]}`)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"redirectURIs": [{"ID": "`+id+`", "URI": "https://lockbox.dev/", "isBaseURI": true, "createdAt": "`+createdAtStamp+`", "createdBy": "`+createdBy+`", "createdByIP": "1.1.1.1", "clientID": "`+clientID+`"}, {"ID": "`+id2+`", "URI": "https://impractical.co/auth", "isBaseURI": false, "createdAt": "`+createdAtStamp+`", "createdBy": "`+createdBy+`", "createdByIP": "1.1.1.1", "clientID": "`+clientID+`"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})

	results, err := client.Clients.CreateRedirectURIs(ctx, clientID, []RedirectURI{
		{
			URI:       "https://lockbox.dev/",
			IsBaseURI: true,
		},
		{
			URI: "https://impractical.co/auth",
		},
	})
	if err != nil {
		t.Fatalf("Error creating redirect URIs: %s", err)
	}
	if diff := cmp.Diff([]RedirectURI{
		{
			ID:          id,
			URI:         "https://lockbox.dev/",
			IsBaseURI:   true,
			ClientID:    clientID,
			CreatedAt:   createdAt,
			CreatedBy:   createdBy,
			CreatedByIP: "1.1.1.1",
		},
		{
			ID:          id2,
			URI:         "https://impractical.co/auth",
			IsBaseURI:   false,
			ClientID:    clientID,
			CreatedAt:   createdAt,
			CreatedBy:   createdBy,
			CreatedByIP: "1.1.1.1",
		},
	}, results); diff != "" {
		t.Errorf("Redirect URI mismatch (-wanted, +got): %s", diff)
	}
}

func TestRedirectURIsCreate_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: HMACAuth{
			MaxSkew: time.Minute,
			OrgKey:  "LOCKBOXTEST",
			Key:     "testkey",
			Secret:  []byte("mysecrethmackey"),
		},
	})

	_, err := client.Clients.CreateRedirectURIs(ctx, "", []RedirectURI{})
	if err != ErrClientRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrClientRequestMissingID, err)
	}
}

func TestRedirectURIsCreate_errors(t *testing.T) {
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
		"notFound": {
			status: http.StatusNotFound,
			body:   []byte(`{"errors":[{"error": "not_found", "param": "id"}]}`),
			err:    ErrClientNotFound,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			clientUUID := uuidOrFail(t)
			redirectUUID := uuidOrFail(t)

			hmacOpts := HMACAuth{
				MaxSkew: time.Minute,
				OrgKey:  "LOCKBOXTEST",
				Key:     "testkey",
				Secret:  []byte("mysecrethmackey"),
			}

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Clients: hmacOpts,
			})

			_, err := client.Clients.CreateRedirectURIs(ctx, clientUUID, []RedirectURI{
				{
					URI:       "https://lockbox.dev/test/" + redirectUUID,
					IsBaseURI: true,
				},
			})

			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestRedirectURIsCreate_missingURI(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "field": "/redirectURIs/0/URI"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: HMACAuth{
			MaxSkew: time.Minute,
			OrgKey:  "LOCKBOXTEST",
			Key:     "testkey",
			Secret:  []byte("mysecrethmackey"),
		},
	})

	id := uuidOrFail(t)

	_, err := client.Clients.CreateRedirectURIs(ctx, id, []RedirectURI{{}})
	if _, ok := err.(ErrRedirectURIURIMissing); !ok {
		t.Errorf("Expected error %T, got %v instead", ErrRedirectURIURIMissing{}, err)
	}
}

func TestRedirectURIsCreate_conflictingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "conflict", "field": "/redirectURIs/0/id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: HMACAuth{
			MaxSkew: time.Minute,
			OrgKey:  "LOCKBOXTEST",
			Key:     "testkey",
			Secret:  []byte("mysecrethmackey"),
		},
	})

	id := uuidOrFail(t)

	_, err := client.Clients.CreateRedirectURIs(ctx, id, []RedirectURI{
		{
			URI:       "https://lockbox.dev/",
			IsBaseURI: true,
		},
	})
	if _, ok := err.(ErrRedirectURIIDConflict); !ok {
		t.Errorf("Expected error %T, got %v instead", ErrRedirectURIIDConflict{}, err)
	}
}

func TestRedirectURIsList_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	createdAt := time.Now().Round(time.Second)
	createdAtStamp := createdAt.Format(time.RFC3339)
	createdBy := "testuser"

	id := uuidOrFail(t)
	id2 := uuidOrFail(t)
	clientID := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/clients/v1/"+url.PathEscape(clientID)+"/redirectURIs")
		checkMethod(t, r, http.MethodGet)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"redirectURIs": [{"ID": "`+id+`", "URI": "https://lockbox.dev/", "isBaseURI": true, "createdAt": "`+createdAtStamp+`", "createdBy": "`+createdBy+`", "createdByIP": "1.1.1.1", "clientID": "`+clientID+`"}, {"ID": "`+id2+`", "URI": "https://impractical.co/auth", "isBaseURI": false, "createdAt": "`+createdAtStamp+`", "createdBy": "`+createdBy+`", "createdByIP": "1.1.1.1", "clientID": "`+clientID+`"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})

	results, err := client.Clients.ListRedirectURIs(ctx, clientID)
	if err != nil {
		t.Fatalf("Error creating redirect URIs: %s", err)
	}
	if diff := cmp.Diff([]RedirectURI{
		{
			ID:          id,
			URI:         "https://lockbox.dev/",
			IsBaseURI:   true,
			ClientID:    clientID,
			CreatedAt:   createdAt,
			CreatedBy:   createdBy,
			CreatedByIP: "1.1.1.1",
		},
		{
			ID:          id2,
			URI:         "https://impractical.co/auth",
			IsBaseURI:   false,
			ClientID:    clientID,
			CreatedAt:   createdAt,
			CreatedBy:   createdBy,
			CreatedByIP: "1.1.1.1",
		},
	}, results); diff != "" {
		t.Errorf("Redirect URI mismatch (-wanted, +got): %s", diff)
	}
}

func TestRedirectURIsList_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: HMACAuth{
			MaxSkew: time.Minute,
			OrgKey:  "LOCKBOXTEST",
			Key:     "testkey",
			Secret:  []byte("mysecrethmackey"),
		},
	})

	_, err := client.Clients.ListRedirectURIs(ctx, "")
	if err != ErrClientRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrClientRequestMissingID, err)
	}
}

func TestRedirectURIsList_errors(t *testing.T) {
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
			err:    ErrClientNotFound,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			clientUUID := uuidOrFail(t)

			hmacOpts := HMACAuth{
				MaxSkew: time.Minute,
				OrgKey:  "LOCKBOXTEST",
				Key:     "testkey",
				Secret:  []byte("mysecrethmackey"),
			}

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Clients: hmacOpts,
			})

			_, err := client.Clients.ListRedirectURIs(ctx, clientUUID)
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}

func TestRedirectURIsDelete_success(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	createdAt := time.Now().Round(time.Second)
	createdAtStamp := createdAt.Format(time.RFC3339)
	createdBy := "testuser"

	id := uuidOrFail(t)
	clientID := uuidOrFail(t)

	hmacOpts := HMACAuth{
		MaxSkew: time.Minute,
		OrgKey:  "LOCKBOXTEST",
		Key:     "testkey",
		Secret:  []byte("mysecrethmackey"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkURL(t, r, "/clients/v1/"+url.PathEscape(clientID)+"/redirectURIs/"+url.PathEscape(id))
		checkMethod(t, r, http.MethodDelete)
		checkHMACAuthorization(t, r, hmacOpts)

		w.WriteHeader(http.StatusOK)
		mustWrite(t, w, []byte(`{"redirectURIs": [{"ID": "`+id+`", "URI": "https://lockbox.dev/", "isBaseURI": true, "createdAt": "`+createdAtStamp+`", "createdBy": "`+createdBy+`", "createdByIP": "1.1.1.1", "clientID": "`+clientID+`"}]}`))
	}))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: hmacOpts,
	})

	err := client.Clients.DeleteRedirectURI(ctx, clientID, id)
	if err != nil {
		t.Fatalf("Error creating redirect URIs: %s", err)
	}
}

func TestRedirectURIsDelete_missingID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: HMACAuth{
			MaxSkew: time.Minute,
			OrgKey:  "LOCKBOXTEST",
			Key:     "testkey",
			Secret:  []byte("mysecrethmackey"),
		},
	})

	clientID := uuidOrFail(t)

	err := client.Clients.DeleteRedirectURI(ctx, clientID, "")
	if err != ErrClientRequestMissingRedirectURIID {
		t.Errorf("Expected error %v, got %v instead", ErrClientRequestMissingRedirectURIID, err)
	}
}

func TestRedirectURIsDelete_missingURIID(t *testing.T) {
	t.Parallel()
	log := yall.New(testinglog.New(t, yall.Debug))
	ctx := yall.InContext(context.Background(), log)

	server := staticResponseServer(t, http.StatusBadRequest, []byte(`{"errors":[{"error": "missing", "param": "id"}]}`))
	defer server.Close()

	client := testClient(ctx, t, server.URL, HMACCredentials{
		Clients: HMACAuth{
			MaxSkew: time.Minute,
			OrgKey:  "LOCKBOXTEST",
			Key:     "testkey",
			Secret:  []byte("mysecrethmackey"),
		},
	})

	id := uuidOrFail(t)

	err := client.Clients.DeleteRedirectURI(ctx, "", id)
	if err != ErrClientRequestMissingID {
		t.Errorf("Expected error %v, got %v instead", ErrClientRequestMissingID, err)
	}
}

func TestRedirectURIsDelete_errors(t *testing.T) {
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
		"clientNotFound": {
			status: http.StatusNotFound,
			body:   []byte(`{"errors":[{"error": "not_found", "param": "id"}]}`),
			err:    ErrClientNotFound,
		},
		"notFound": {
			status: http.StatusNotFound,
			body:   []byte(`{"errors":[{"error": "not_found", "param": "uri"}]}`),
			err:    ErrClientRedirectURINotFound,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := yall.New(testinglog.New(t, yall.Debug))
			ctx := yall.InContext(context.Background(), log)

			clientUUID := uuidOrFail(t)
			id := uuidOrFail(t)

			hmacOpts := HMACAuth{
				MaxSkew: time.Minute,
				OrgKey:  "LOCKBOXTEST",
				Key:     "testkey",
				Secret:  []byte("mysecrethmackey"),
			}

			server := staticResponseServer(t, test.status, test.body)
			defer server.Close()

			client := testClient(ctx, t, server.URL, HMACCredentials{
				Clients: hmacOpts,
			})

			err := client.Clients.DeleteRedirectURI(ctx, clientUUID, id)
			if err != test.err {
				t.Errorf("Expected error %v, got %v instead", test.err, err)
			}
		})
	}
}
