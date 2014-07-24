package response_type_test

import (
	"net/url"
	"testing"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/response_type"
	"github.com/arjantop/gopherauth/testutil"
	"github.com/stretchr/testify/assert"
)

type tokenDeps struct {
	params     url.Values
	controller *response_type.TokenController
}

func makeTokenController() tokenDeps {
	params := makeTokenRequestParameters()
	return tokenDeps{
		params:     params,
		controller: response_type.NewTokenController(),
	}
}

func makeTokenRequestParameters() url.Values {
	return map[string][]string{
		"response_type": []string{"token"},
		"client_id":     []string{"client_id"},
		"redirect_uri":  []string{"https://example.com/callback"},
		"scope":         []string{"scope1 scope2"},
		"state":         []string{"state"},
	}
}

func TestTokenParametersAreExtracted(t *testing.T) {
	deps := makeTokenController()

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
