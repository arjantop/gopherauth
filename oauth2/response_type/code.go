package response_type

import (
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
)

type CodeController struct {
}

func NewCodeController() *CodeController {
	return &CodeController{}
}

func (c *CodeController) ExtractParameters(r *http.Request) url.Values {
	query := r.URL.Query()
	clientId := query.Get(oauth2.ParameterClientId)
	redirectUri := query.Get(oauth2.ParameterRedirectUri)
	state := query.Get(oauth2.ParameterState)
	scopeString := query.Get(oauth2.ParameterScope)

	params := url.Values{}
	params.Add(oauth2.ParameterClientId, clientId)
	params.Add(oauth2.ParameterRedirectUri, redirectUri)
	params.Add(oauth2.ParameterState, state)
	params.Add(oauth2.ParameterScope, scopeString)

	return params
}
