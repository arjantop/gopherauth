package grant_type_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/grant_type"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/testutil"
	"github.com/stretchr/testify/assert"
)

const redirectUri = "https://domain.com/callback"

func makeAuthCodeParameters() url.Values {
	return map[string][]string{
		"grant_type":   []string{"authentication_code"},
		"code":         []string{"auth_code"},
		"redirect_uri": []string{redirectUri},
	}
}

type authCodeDeps struct {
	oauth2Service *service.Oauth2ServiceMock
	controller    *grant_type.AuthorizationCodeController
	params        url.Values
}

func makeAuthCodeController() authCodeDeps {
	oauth2Service := service.NewOauth2ServiceMock()
	return authCodeDeps{
		oauth2Service: oauth2Service,
		controller:    grant_type.NewAuthorizationCodeController(oauth2Service),
		params:        makeAuthCodeParameters(),
	}
}

func TestAuthCodeMissingParemeterCode(t *testing.T) {
	deps := makeAuthCodeController()
	assertMissingParameter(t, deps.controller, deps.params, "code")
}

func TestAuthCodeMissingParameterRedirectUri(t *testing.T) {
	deps := makeAuthCodeController()
	assertMissingParameter(t, deps.controller, deps.params, "redirect_uri")
}

func TestAuthCodeRespondsReturnsBearerToken(t *testing.T) {
	deps := makeAuthCodeController()

	clientCredentials := service.ClientCredentials{"client_id", "client_secret"}
	tokenResponse := oauth2.AccessTokenResponse{"token", "bearer", 3600}
	deps.oauth2Service.On(
		"AuthorizationCode",
		&clientCredentials,
		"auth_code",
		redirectUri).Return(&tokenResponse, nil)

	request := testutil.NewEndpointRequest(t, "POST", "token", deps.params)
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assertResponseValid(t, &tokenResponse, recorder)
}

func TestAuthTokenMissingClientCredentials(t *testing.T) {
	deps := makeAuthCodeController()
	assertMissingCredentialsError(t, deps.controller, deps.params)
}

func TestAuthCodeOauth2ServiceStandardErrorIsDisplayed(t *testing.T) {
	deps := makeAuthCodeController()

	clientCredentials := service.ClientCredentials{"client_id", "client_secret"}
	errorResponse := oauth2.ErrorResponse{
		oauth2.ErrorUnauthorizedClient, "Unauthorized client", nil}
	deps.oauth2Service.On(
		"AuthorizationCode",
		&clientCredentials,
		"auth_code",
		redirectUri).Return(nil, &errorResponse)

	request := testutil.NewEndpointRequest(t, "POST", "token", deps.params)
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)

	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)

	assert.Equal(t, 2, len(jsonMap))
	assert.Equal(t, oauth2.ErrorUnauthorizedClient, jsonMap["error"],
		"Error should be unuthorized client", recorder.Body.String())
	assert.NotEmpty(t, jsonMap["error_description"],
		"Error description should not be empty", recorder.Body.String())
}

func TestAuthCodeOauthServiceErrorResultsInServiceUnavaliableError(t *testing.T) {
	deps := makeAuthCodeController()
	clientCredentials := service.ClientCredentials{"client_id", "client_secret"}
	errorResponse := errors.New("error")
	deps.oauth2Service.On(
		"AuthorizationCode",
		&clientCredentials,
		"auth_code",
		redirectUri).Return(nil, errorResponse)

	request := testutil.NewEndpointRequest(t, "POST", "token", deps.params)
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}
