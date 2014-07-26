package response_type

import (
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
)

func extractParameters(r *http.Request) url.Values {
	query := r.URL.Query()
	responseType := query.Get(oauth2.ParameterResponseType)
	clientId := query.Get(oauth2.ParameterClientId)
	redirectUri := query.Get(oauth2.ParameterRedirectUri)
	scope := query.Get(oauth2.ParameterScope)
	state := query.Get(oauth2.ParameterState)

	params := url.Values{}
	params.Add(oauth2.ParameterResponseType, responseType)
	params.Add(oauth2.ParameterClientId, clientId)
	params.Add(oauth2.ParameterRedirectUri, redirectUri)
	params.Add(oauth2.ParameterState, state)
	params.Add(oauth2.ParameterScope, scope)

	return params
}
