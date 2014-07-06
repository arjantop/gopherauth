package grant_type_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/grant_type"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/testutil"
)

const (
	serviceUrl = "https://example.com"
)

func makeParameters() url.Values {
	return map[string][]string{
		"grant_type": []string{"password"},
		"username":   []string{"user"},
		"password":   []string{"pass"},
	}
}

type deps struct {
	oauth2Service *service.Oauth2ServiceMock
	controller    *grant_type.PasswordController
	params        url.Values
}

func makePasswordController() deps {
	oauth2Service := service.NewOauth2ServiceMock()
	return deps{
		oauth2Service: oauth2Service,
		controller:    grant_type.NewPasswordController(oauth2Service),
		params:        makeParameters(),
	}
}

func tokenEndpointRequest(t *testing.T, method string, params url.Values) *http.Request {
	getParams := ""
	if method == "GET" {
		getParams = "?" + params.Encode()
	}
	var postParams io.Reader
	if method == "POST" {
		postParams = strings.NewReader(params.Encode())
	}
	request, err := http.NewRequest(method, serviceUrl+"/token"+getParams, postParams)
	assert.Nil(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func assertResponseValid(
	t *testing.T,
	tokenResponse *oauth2.AccessTokenResponse,
	recorder *httptest.ResponseRecorder) {

	assert.Equal(t, http.StatusOK, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)
	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)
	assert.Equal(t, 3, len(jsonMap))
	assert.Equal(t, tokenResponse.AccessToken, jsonMap["access_token"])
	assert.Equal(t, tokenResponse.TokenType, jsonMap["token_type"])
	assert.Equal(t, tokenResponse.ExpiresIn, jsonMap["expires_in"])
}

func TestPasswordFlowReturnsBearerToken(t *testing.T) {
	deps := makePasswordController()
	clientCredentials := service.ClientCredentials{"client_id", "client_secret"}
	tokenResponse := oauth2.AccessTokenResponse{"token", "bearer", 3600}
	deps.oauth2Service.On("PasswordFlow", &clientCredentials, "user", "pass").Return(&tokenResponse, nil)

	recorder := httptest.NewRecorder()
	request := tokenEndpointRequest(t, "POST", deps.params)
	request.SetBasicAuth("client_id", "client_secret")

	deps.controller.ServeHTTP(recorder, request)

	assertResponseValid(t, &tokenResponse, recorder)
}

func assertMissingParameter(t *testing.T, name string) {
	deps := makePasswordController()
	deps.params.Del(name)
	request := tokenEndpointRequest(t, "POST", deps.params)
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)
	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)
	assert.Equal(t, 2, len(jsonMap))
	assert.Equal(t, oauth2.ErrorInvalidRequest, jsonMap["error"])
	assert.NotEmpty(t, jsonMap["error_description"])
}

func TestPasswordFlowMissingParameterUsername(t *testing.T) {
	assertMissingParameter(t, "username")
}

func TestPasswordFlowMissingParameterPassword(t *testing.T) {
	assertMissingParameter(t, "password")
}

func TestPasswordFlowMissingClientCredentials(t *testing.T) {
	deps := makePasswordController()
	request := tokenEndpointRequest(t, "POST", deps.params)

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)
	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)
	assert.Equal(t, 1, len(jsonMap))
	assert.Equal(t, oauth2.ErrorInvalidClient, jsonMap["error"])
}

func TestOauthServiceResponseErrorIsReturned(t *testing.T) {
	deps := makePasswordController()
	clientCredentials := service.ClientCredentials{"client_id", "client_secret"}
	errorResponse := oauth2.ErrorResponse{oauth2.ErrorInvalidClient, "", nil}
	deps.oauth2Service.On("PasswordFlow", &clientCredentials, "user", "pass").Return(nil, &errorResponse)

	request := tokenEndpointRequest(t, "POST", makeParameters())
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)
	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)
	assert.Equal(t, 1, len(jsonMap))
	assert.Equal(t, oauth2.ErrorInvalidClient, jsonMap["error"])
}

func TestOauthServiceErrorCausesInternalServerError(t *testing.T) {
	deps := makePasswordController()
	clientCredentials := service.ClientCredentials{"client_id", "client_secret"}
	errorResponse := errors.New("some error")
	deps.oauth2Service.On("PasswordFlow", &clientCredentials, "user", "pass").Return(nil, errorResponse)

	request := tokenEndpointRequest(t, "POST", makeParameters())
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
}
