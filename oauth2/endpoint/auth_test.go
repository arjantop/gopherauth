package endpoint_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/arjantop/gopherauth/oauth2/endpoint"
	"github.com/arjantop/gopherauth/util"
)

const (
	serviceUrl      = "https://example.com"
	contentTypeHtml = "text/html; charset=utf-8"
	endpointUrl     = serviceUrl + "/auth"
	templatesRoot   = "../../templates"
)

func TestAuthEndpointIsDefinedOnlyForGetHttpMethod(t *testing.T) {
	httpMethods := []string{"POST", "HEAD", "PUT", "DELETE",
		"TRACE", "OPTIONS", "CONNECT", "PATCH"}
	for _, method := range httpMethods {
		endpoint := endpoint.NewAuthEndpointHandler(nil, nil)

		request, err := http.NewRequest(method, endpointUrl, nil)
		assert.Nil(t, err)

		recorder := httptest.NewRecorder()
		endpoint.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code,
			fmt.Sprintf("Auth endpoint should not be defined for %s", method))
	}
}

func TestResponseTypeCodeRequestIsDelegatedToCorrectController(t *testing.T) {
	var ctrlCalled bool
	authCodeGrantCtrl := func(w http.ResponseWriter, r *http.Request) {
		if ctrlCalled {
			assert.Fail(t, "Controller must only be called once")
		}
		ctrlCalled = true
	}
	endpoint := endpoint.NewAuthEndpointHandler(http.HandlerFunc(authCodeGrantCtrl), nil)

	params := url.Values{}
	params.Add("response_type", "code")
	request, err := http.NewRequest("GET", endpointUrl+"?"+params.Encode(), nil)
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	endpoint.ServeHTTP(recorder, request)

	assert.True(t, ctrlCalled, "Auth Code Grant controlled should be called")
}

func assertIsBadRequest(t *testing.T, recorder *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusBadRequest, recorder.Code, "Response code should be 400 Bad Request")
	assert.Equal(t, contentTypeHtml, recorder.Header().Get("Content-Type"), "Response type should be html")
}

func TestErrorIsDisplayedIfResponseTypeIsMissing(t *testing.T) {
	endpoint := endpoint.NewAuthEndpointHandler(nil, util.NewTemplateFactory(templatesRoot))

	params := url.Values{}
	request, err := http.NewRequest("GET", endpointUrl+"?"+params.Encode(), nil)
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	endpoint.ServeHTTP(recorder, request)

	assertIsBadRequest(t, recorder)
}

func TestErrorIsDisplayedIfResponseTypeIsNotSupported(t *testing.T) {
	endpoint := endpoint.NewAuthEndpointHandler(nil, util.NewTemplateFactory(templatesRoot))

	params := url.Values{}
	params.Add("response_type", "unsupported")
	request, err := http.NewRequest("GET", endpointUrl+"?"+params.Encode(), nil)
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	endpoint.ServeHTTP(recorder, request)

	assertIsBadRequest(t, recorder)
}

func TestNoCacheHeadersAreSet(t *testing.T) {
	endpoint := endpoint.NewAuthEndpointHandler(nil, util.NewTemplateFactory(templatesRoot))

	request, err := http.NewRequest("GET", endpointUrl, nil)
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	endpoint.ServeHTTP(recorder, request)

	assert.Equal(t, recorder.Header().Get("Cache-Control"), "no-store", "Cache-Control header should be set")
	assert.Equal(t, recorder.Header().Get("Pragma"), "no-cache", "Pragma header should be set")
}
