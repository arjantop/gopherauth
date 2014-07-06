package endpoint_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/endpoint"
)

func makeParameters() url.Values {
	return map[string][]string{
		"grant_type": []string{"password"},
		"username":   []string{"user"},
		"password":   []string{"pass"},
	}
}

func TestOnlyPostMethodIsAllowed(t *testing.T) {
	httpMethods := []string{"GET", "HEAD", "PUT", "DELETE",
		"TRACE", "OPTIONS", "CONNECT", "PATCH"}
	for _, method := range httpMethods {
		handler := endpoint.NewTokenEndpointHandler(nil)
		recorder := httptest.NewRecorder()

		request, err := http.NewRequest(
			method, "https://example.com/token", strings.NewReader("body"))
		assert.Nil(t, err)

		handler.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code,
			fmt.Sprintf("Auth endpoint should not be defined for %s", method))

	}
}

func TestNoCachingHeadersAreSetOnTokenEndpoint(t *testing.T) {
	handler := endpoint.NewTokenEndpointHandler(nil)
	recorder := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "https://example.com/token", nil)
	assert.Nil(t, err)

	handler.ServeHTTP(recorder, request)

	assert.Equal(t, recorder.Header().Get("Cache-Control"), "no-store")
	assert.Equal(t, recorder.Header().Get("Pragma"), "no-cache")
}

func TestErrorIsDisplayedIfGrantTypeIsunsupported(t *testing.T) {
	handler := endpoint.NewTokenEndpointHandler(nil)

	params := url.Values{}
	params.Add("grant_type", "unsupported")
	postParams := strings.NewReader(params.Encode())
	request, err := http.NewRequest("POST", "https://example.com/token", postParams)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)
	assert.Equal(t, oauth2.ErrorUnsupportedGrantType, jsonMap["error"])
}

func TestGrantTypePasswordControllerIsCalled(t *testing.T) {
	var ctrlCalled bool
	passwordCtrl := func(w http.ResponseWriter, r *http.Request) {
		if ctrlCalled {
			assert.Fail(t, "Controller must only be called once")
		}
		ctrlCalled = true
	}
	handler := endpoint.NewTokenEndpointHandler(http.HandlerFunc(passwordCtrl))

	params := url.Values{}
	params.Add("grant_type", "password")
	postParams := strings.NewReader(params.Encode())
	request, err := http.NewRequest("POST", "https://example.com/token", postParams)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.True(t, ctrlCalled, "Grant type password controller should be called")
}

func TestClientCredentialsInFormDataAreInsertedIntoHeader(t *testing.T) {
	tokenCtrl := func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.NotEmpty(t, authHeader, "Authorization header should be set")
	}
	handler := endpoint.NewTokenEndpointHandler(http.HandlerFunc(tokenCtrl))

	params := url.Values{}
	params.Add("grant_type", "password")
	params.Add("client_id", "client_id")
	params.Add("client_secret", "client_secret")
	postParams := strings.NewReader(params.Encode())
	request, err := http.NewRequest("POST", "https://example.com/token", postParams)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.NotEqual(t, http.StatusBadRequest, recorder.Code, "Response should not be bad Request")
}

func TestClientCredentialsInAuthHeaderHaveHigherPrioriy(t *testing.T) {
	var authHeader string
	tokenCtrl := func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
	}
	handler := endpoint.NewTokenEndpointHandler(http.HandlerFunc(tokenCtrl))

	params := url.Values{}
	params.Add("grant_type", "password")
	params.Add("client_id", "wrong_id")
	params.Add("client_secret", "wrong_secret")
	postParams := strings.NewReader(params.Encode())
	request, err := http.NewRequest("POST", "https://example.com/token", postParams)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("client_id", "client_secret")
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, request.Header.Get("Authorization"), authHeader,
		"Form data client credentials should not be in header")
}
