package grant_type_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func makePasswordParameters() url.Values {
	return map[string][]string{
		"grant_type": []string{"password"},
		"username":   []string{"user"},
		"password":   []string{"pass"},
	}
}

type passwordDeps struct {
	oauth2Service *service.Oauth2ServiceMock
	controller    *grant_type.PasswordController
	params        url.Values
}

func makePasswordController() passwordDeps {
	oauth2Service := service.NewOauth2ServiceMock()
	return passwordDeps{
		oauth2Service: oauth2Service,
		controller:    grant_type.NewPasswordController(oauth2Service),
		params:        makePasswordParameters(),
	}
}

func TestPasswordFlowReturnsBearerToken(t *testing.T) {
	deps := makePasswordController()
	clientCredentials := service.ClientCredentials{"client_id", "client_secret"}
	tokenResponse := oauth2.AccessTokenResponse{"token", "bearer", 3600}
	deps.oauth2Service.On("PasswordFlow", &clientCredentials, "user", "pass").Return(&tokenResponse, nil)

	request := testutil.NewEndpointRequest(t, "POST", "token", deps.params)
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assertResponseValid(t, &tokenResponse, recorder)
}

func TestPasswordFlowMissingParameterUsername(t *testing.T) {
	deps := makePasswordController()
	assertMissingParameter(t, deps.controller, deps.params, "username")
}

func TestPasswordFlowMissingParameterPassword(t *testing.T) {
	deps := makePasswordController()
	assertMissingParameter(t, deps.controller, deps.params, "password")
}

func TestPasswordFlowMissingClientCredentials(t *testing.T) {
	deps := makePasswordController()
	assertMissingCredentialsError(t, deps.controller, deps.params)
}

func TestOauthServiceResponseErrorIsReturned(t *testing.T) {
	deps := makePasswordController()
	clientCredentials := service.ClientCredentials{"client_id", "client_secret"}
	errorResponse := oauth2.ErrorResponse{oauth2.ErrorInvalidClient, "", nil}
	deps.oauth2Service.On("PasswordFlow", &clientCredentials, "user", "pass").Return(nil, &errorResponse)

	request := testutil.NewEndpointRequest(t, "POST", "token", deps.params)
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

func TestPasswordOauthServiceErrorResultsInServiceUnavaliableError(t *testing.T) {
	deps := makePasswordController()
	clientCredentials := service.ClientCredentials{"client_id", "client_secret"}
	errorResponse := errors.New("some error")
	deps.oauth2Service.On(
		"PasswordFlow",
		&clientCredentials,
		"user", "pass").Return(nil, errorResponse)

	request := testutil.NewEndpointRequest(t, "POST", "token", deps.params)
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}
