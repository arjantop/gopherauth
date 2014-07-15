package response_type_test

import (
	"net/url"
	"testing"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/response_type"
	"github.com/arjantop/gopherauth/testutil"
	"github.com/stretchr/testify/assert"
)

type deps struct {
	params     url.Values
	controller *response_type.CodeController
}

func makeAuthCodeController() deps {
	params := makeAuthCodeRequestParameters()
	return deps{
		params:     params,
		controller: response_type.NewCodeController(),
	}
}

func (d *deps) getScope() []string {
	return oauth2.ParseScope(d.params.Get("scope"))
}

func makeAuthCodeRequestParameters() url.Values {
	return map[string][]string{
		"response_type": []string{"code"},
		"client_id":     []string{"client_id"},
		"redirect_uri":  []string{"https://example.com/callback"},
		"scope":         []string{"scope1 scope2"},
		"state":         []string{"state"},
	}
}

func TestAuthCodeParametersAreExtracted(t *testing.T) {
	deps := makeAuthCodeController()

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
