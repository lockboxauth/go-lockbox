package lockbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/hashicorp/go-multierror"
)

const (
	requestErrAccessDenied  = "access_denied"
	requestErrInvalidValue  = "invalid_value"
	requestErrInvalidFormat = "invalid_format"
	requestErrMissing       = "missing"
	requestErrNotFound      = "not_found"
	requestErrConflict      = "conflict"
	requestErrActOfGod      = "act_of_god"
)

var (
	serverError        = RequestError{Slug: requestErrActOfGod}
	invalidFormatError = RequestError{Slug: requestErrInvalidFormat, Field: "/"}
)

var (
	// ErrServerError is returned when a server error is encountered while
	// making a request. Users typically can't do anything about these, and
	// they should be reported as bugs.
	ErrServerError = errors.New("server error")

	// ErrInvalidFormatError is returned when the server couldn't parse
	// the request as made. Users typically can't do anything about these,
	// and they should be reported as bugs against go-lockbox.
	ErrInvalidFormatError = errors.New("invalid request")

	// ErrInvalidRequestError is returned when the server rejected the
	// request, without giving more information as to why.
	ErrInvalidRequestError = errors.New("invalid request")

	// ErrUnauthorized is returned when a request is made that the Client
	// is not authorized to make. Check the credentials and try again.
	ErrUnauthorized = errors.New("unauthorized request")

	// ErrUnexpectedError is returned when a RequestError is returned in a
	// Response that the cliente doesn't know how to handle. This is
	// usually indicative of a bug in go-lockbox and an issue whould be
	// filed about it. The logs can provide more information on what the
	// error is.
	ErrUnexpectedError = errors.New("unexpected error in response")

	// ErrUnexpectedResponse is returned when a Response is returned that
	// doesn't make sense or that go-lockbox wasn't expecting. It's often
	// used in situations where ignoring it would cause a panic. This is
	// usually indicative of a bug in go-lockbox or the server, and an
	// issue should be filed about it. There's not much a caller can do
	// about these errors.
	ErrUnexpectedResponse = errors.New("unexpected response")
)

// Response is the standard response format we get back from every service,
// except the oauth2 service, which follows the standard.
type Response struct {
	Accounts     []Account     `json:"accounts,omitempty"`
	Clients      []APIClient   `json:"clients,omitempty"`
	RedirectURIs []RedirectURI `json:"redirectURIs,omitempty"`
	Scopes       []Scope       `json:"scopes,omitempty"`
	Errors       RequestErrors `json:"errors,omitempty"`
}

func responseFromBody(resp *http.Response) (res Response, returnErr error) {
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			returnErr = multierror.Append(returnErr, fmt.Errorf("error closing response body: %w", err))
		}
	}()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Response{}, fmt.Errorf("error reading response body: %w", err)
	}
	res = Response{}
	err = json.Unmarshal(b, &res)
	if err != nil {
		return Response{}, fmt.Errorf("error parsing response body: %w", err)
	}
	return res, nil
}

func oauthResponse(resp *http.Response) (res OAuth2Response, returnErr error) {
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			returnErr = multierror.Append(returnErr, fmt.Errorf("error closing response body: %w", err))
		}
	}()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return OAuth2Response{}, fmt.Errorf("error reading response body: %w", err)
	}
	res = OAuth2Response{}
	err = json.Unmarshal(respBody, &res)
	if err != nil {
		return res, fmt.Errorf("error parsing response body %q: %w", string(respBody), err)
	}
	return res, nil
}

// OAuth2ResponseFromParams decodes the URL parameters passed in and returns an
// OAuth2Response from their values.
func OAuth2ResponseFromParams(vals url.Values) (OAuth2Response, error) {
	var expiresIn int
	if e := vals.Get("expires_in"); e != "" {
		eint, err := strconv.Atoi(e)
		if err != nil {
			return OAuth2Response{}, fmt.Errorf("error parsing expires_in as integer: %w", err)
		}
		expiresIn = eint
	}
	return OAuth2Response{
		AccessToken:  vals.Get("access_token"),
		TokenType:    vals.Get("token_type"),
		ExpiresIn:    expiresIn,
		RefreshToken: vals.Get("refresh_token"),
		Scope:        vals.Get("scope"),
		Error:        vals.Get("error"),
	}, nil
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

// FieldMatches checks if any RequestError in e has the specified slug and a
// field that matches the passed regular expression.
func (e RequestErrors) FieldMatches(slug string, reg *regexp.Regexp) [][]string {
	for _, candidate := range e {
		if candidate.Slug != slug {
			continue
		}
		if reg.MatchString(candidate.Field) {
			return reg.FindAllStringSubmatch(candidate.Field, -1)
		}
	}
	return nil
}

func jsonRequest(r *http.Request) {
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
}
