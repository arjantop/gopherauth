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

func TestPasswordParametersAreExtracted(t *testing.T) {
	deps := makePasswordController()

	request := testutil.NewEndpointRequest(t, "POST", "token", deps.params)
	params := deps.controller.ExtractParameters(request)
	for paramName, _ := range deps.params {
		assert.Equal(t, deps.params.Get(paramName), params.Get(paramName),
			"Parameter: %s", paramName)
	}
}

func TestPasswordResponseIsReturned(t *testing.T) {
	deps := makePasswordController()

	clientCredentials := &service.ClientCredentials{"client_id", "client_secret"}
	expectedResponse := &oauth2.AccessTokenResponse{}

	deps.oauth2Service.On(
		"Password",
		clientCredentials,
		"user",
		"pass").Return(expectedResponse, nil)

	response, err := deps.controller.Execute(clientCredentials, deps.params)

	assert.Nil(t, err)
	assert.Equal(t, expectedResponse, response)
}

func TestPasswordServiceErrorIsReturned(t *testing.T) {
	deps := makePasswordController()

	clientCredentials := &service.ClientCredentials{"client_id", "client_secret"}

	deps.oauth2Service.On(
		"Password",
		clientCredentials,
		"user",
		"pass").Return(nil, errors.New("error"))

	response, err := deps.controller.Execute(clientCredentials, deps.params)

	assert.Nil(t, response)
	assert.Equal(t, errors.New("error"), err)
}
