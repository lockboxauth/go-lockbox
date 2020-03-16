package lockbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	requestErrAccessDenied  = "access_denied"
	requestErrInsufficient  = "insufficient"
	requestErrOverflow      = "overflow"
	requestErrInvalidValue  = "invalid_value"
	requestErrInvalidFormat = "invalid_format"
	requestErrMissing       = "missing"
	requestErrNotFound      = "not_found"
	requestErrConflict      = "conflict"
	requestErrActOfGod      = "act_of_god"
)

var (
	serverError = RequestError{Slug: requestErrActOfGod}
)

var (
	// ErrServerError is returned when a server error is encountered while
	// making a request. Users typically can't do anything about these, and
	// they should be reported as bugs.
	ErrServerError = errors.New("server error")
)

// Response is the standard response format we get back from every service,
// except the oauth2 service, which follows the standard.
type Response struct {
	Accounts     []Account     `json:"accounts,omitempty"`
	Clients      []APIClient   `json:"clients,omitempty"`
	RedirectURIs []RedirectURI `json:"redirect_uris,omitempty"`
	Scopes       []Scope       `json:"scopes,omitempty"`
	Errors       RequestErrors `json:"errors,omitempty"`
}

func responseFromBody(resp *http.Response) (Response, error) {
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Response{}, fmt.Errorf("error reading response body: %w", err)
	}
	var res Response
	err = json.Unmarshal(b, &res)
	if err != nil {
		return Response{}, fmt.Errorf("error parsing response body: %w", err)
	}
	return res, nil
}

// RequestError describes an error that an HTTP request encountered, hopefully
// with enough information to point to a single root cause.
type RequestError struct {
	Slug   string `json:"error,omitempty"`
	Field  string `json:"field,omitempty"`
	Param  string `json:"param,omitempty"`
	Header string `json:"header,omitempty"`
}

// Equal returns true if two RequestErrors should be considered equivalent.
func (e RequestError) Equal(other RequestError) bool {
	if e.Slug != other.Slug {
		return false
	}
	if e.Field != other.Field {
		return false
	}
	if e.Param != other.Param {
		return false
	}
	if e.Header != other.Header {
		return false
	}
	return true
}

// RequestErrors is a collection of RequestErrors, describing all known errors
// with a request. It has its own type to facilitate helper methods.
type RequestErrors []RequestError

// Contains returns true if the RequestError can be found in the RequestErrors.
func (e RequestErrors) Contains(err RequestError) bool {
	for _, candidate := range e {
		if candidate.Equal(err) {
			return true
		}
	}
	return false
}

func jsonRequest(r *http.Request) {
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
}
