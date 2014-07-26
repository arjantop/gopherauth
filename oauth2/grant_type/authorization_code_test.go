package grant_type_test

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/grant_type"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/testutil"
)

func makeAuthCodeParameters() url.Values {
	return map[string][]string{
		"grant_type":   []string{"authentication_code"},
		"code":         []string{"auth_code"},
		"redirect_uri": []string{"https://domain.com/callback"},
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

func TestAuthCodeParametersAreExtracted(t *testing.T) {
	deps := makeAuthCodeController()

	request := testutil.NewEndpointRequest(t, "POST", "token", deps.params)
	params := deps.controller.ExtractParameters(request)
	for paramName, _ := range deps.params {
		assert.Equal(t, deps.params.Get(paramName), params.Get(paramName),
			"Parameter: %s", paramName)
	}
}

func TestAuthCodeResponseIsReturned(t *testing.T) {
	deps := makeAuthCodeController()

	clientCredentials := &service.ClientCredentials{"client_id", "client_secret"}
	expectedResponse := &oauth2.AccessTokenResponse{}
	uri, _ := url.Parse(deps.params.Get("redirect_uri"))

	deps.oauth2Service.On(
		"AuthorizationCode",
		clientCredentials,
		deps.params.Get("code"),
		uri).Return(expectedResponse, nil)

	response, err := deps.controller.Execute(clientCredentials, deps.params)

	assert.Nil(t, err)
	assert.Equal(t, expectedResponse, response)
}

func TestAuthCodeServiceErrorIsReturned(t *testing.T) {
	deps := makeAuthCodeController()

	clientCredentials := &service.ClientCredentials{"client_id", "client_secret"}
	uri, _ := url.Parse(deps.params.Get("redirect_uri"))

	deps.oauth2Service.On(
		"AuthorizationCode",
		clientCredentials,
		deps.params.Get("code"),
		uri).Return(nil, errors.New("error"))

	response, err := deps.controller.Execute(clientCredentials, deps.params)

	assert.Nil(t, response)
	assert.Equal(t, errors.New("error"), err)
}
