package grant_type

import (
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/service"
)

type PasswordController struct {
	oauth2Service service.Oauth2Service
}

func NewPasswordController(oauth2Service service.Oauth2Service) *PasswordController {
	return &PasswordController{
		oauth2Service: oauth2Service,
	}
}

func (c *PasswordController) ExtractParameters(r *http.Request) url.Values {
	grantType := r.PostFormValue(oauth2.ParameterGrantType)
	username := r.PostFormValue(oauth2.ParameterUsername)
	password := r.PostFormValue(oauth2.ParameterPassword)

	params := url.Values{}
	params.Add(oauth2.ParameterGrantType, grantType)
	params.Add(oauth2.ParameterUsername, username)
	params.Add(oauth2.ParameterPassword, password)

	return params
}

func (c *PasswordController) Execute(
	clientCredentials *service.ClientCredentials,
	params url.Values) (*oauth2.AccessTokenResponse, error) {

	username := params.Get(oauth2.ParameterUsername)
	password := params.Get(oauth2.ParameterPassword)

	return c.oauth2Service.Password(clientCredentials, username, password)
}
