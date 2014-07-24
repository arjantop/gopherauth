package response_type_test

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/response_type"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/testutil"
)

type deps struct {
	params        url.Values
	oauth2Service *service.Oauth2ServiceMock
	controller    *response_type.CodeController
}

func makeCodeController() deps {
	params := makeCodeRequestParameters()
	oauth2Service := service.NewOauth2ServiceMock()
	return deps{
		params:        params,
		oauth2Service: oauth2Service,
		controller:    response_type.NewCodeController(oauth2Service),
	}
}

func makeCodeRequestParameters() url.Values {
	return map[string][]string{
		"response_type": []string{"code"},
		"client_id":     []string{"client_id"},
		"redirect_uri":  []string{"https://example.com/callback"},
		"scope":         []string{"scope1 scope2"},
		"state":         []string{"state"},
	}
}

func TestCodeParametersAreExtracted(t *testing.T) {
	deps := makeCodeController()

	request := testutil.NewEndpointRequest(t, "GET", "auth", deps.params)
	params := deps.controller.ExtractParameters(request)
	for paramName, _ := range deps.params {
		if paramName == oauth2.ParameterResponseType {
			continue
		}
		assert.Equal(t, deps.params.Get(paramName), params.Get(paramName),
			"Parameter: %s", paramName)
	}
}

func TestCodeReturnsCorrectRedirectURL(t *testing.T) {
	deps := makeCodeController()

	response := oauth2.AuthorizationResponse{
		Code:  "code",
		State: "state",
	}

	url, err := url.Parse(deps.params.Get("redirect_uri"))
	assert.Nil(t, err)

	deps.oauth2Service.On(
		"Code",
		deps.params.Get("client_id"),
		url,
		deps.params.Get("scope"),
		deps.params.Get("state")).Return(&response, nil)

	redirectURL, err := deps.controller.Execute(deps.params)

	assert.Nil(t, err)
	assert.Equal(t, "code", redirectURL.Query().Get("code"))
	assert.Equal(t, "state", redirectURL.Query().Get("state"))
}

func TestCodeServiceErrorIsReturned(t *testing.T) {
	deps := makeCodeController()

	url, err := url.Parse(deps.params.Get("redirect_uri"))
	assert.Nil(t, err)

	deps.oauth2Service.On(
		"Code",
		deps.params.Get("client_id"),
		url,
		deps.params.Get("scope"),
		deps.params.Get("state")).Return(nil, errors.New("error"))

	redirectURL, err := deps.controller.Execute(deps.params)

	assert.Equal(t, errors.New("error"), err)
	assert.Nil(t, redirectURL)
}
