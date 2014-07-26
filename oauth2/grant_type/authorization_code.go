package grant_type

import (
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/service"
)

type AuthorizationCodeController struct {
	oauth2Service service.Oauth2Service
}

func NewAuthorizationCodeController(
	oauth2Service service.Oauth2Service) *AuthorizationCodeController {

	return &AuthorizationCodeController{
		oauth2Service: oauth2Service,
	}
}

func (c *AuthorizationCodeController) ExtractParameters(r *http.Request) url.Values {
	grantType := r.PostFormValue(oauth2.ParameterGrantType)
	code := r.PostFormValue(oauth2.ParameterCode)
	redirectURI := r.PostFormValue(oauth2.ParameterRedirectUri)

	params := url.Values{}
	params.Add(oauth2.ParameterGrantType, grantType)
	params.Add(oauth2.ParameterCode, code)
	params.Add(oauth2.ParameterRedirectUri, redirectURI)

	return params
}

func (c *AuthorizationCodeController) Execute(
	clientCredentials *service.ClientCredentials,
	params url.Values) (*oauth2.AccessTokenResponse, error) {

	code := params.Get(oauth2.ParameterCode)
	redirectURIString := params.Get(oauth2.ParameterRedirectUri)
	redirectURI, err := url.Parse(redirectURIString)
	if err != nil {
		return nil, err
	}
	return c.oauth2Service.AuthorizationCode(clientCredentials, code, redirectURI)
}
