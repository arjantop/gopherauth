package grant_type

import (
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/helpers"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/util"
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

func (c *AuthorizationCodeController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientCredentials, err := util.GetBasicAuth(r)
	if err != nil {
		response := helpers.NewMissingClientCredentialsError()
		response.WriteResponse(w, http.StatusUnauthorized)
		return
	}

	code := r.PostFormValue(oauth2.ParameterCode)
	redirect_uri := r.PostFormValue(oauth2.ParameterRedirectUri)

	params := url.Values{}
	params.Add(oauth2.ParameterCode, code)
	params.Add(oauth2.ParameterRedirectUri, redirect_uri)

	valid := helpers.ValidateParameters(params, w)
	if !valid {
		return
	}

	response, err := c.oauth2Service.AuthorizationCode(clientCredentials, code, redirect_uri)
	if err != nil {
		if response, ok := err.(*oauth2.ErrorResponse); ok {
			response.WriteResponse(w, http.StatusBadRequest)
		} else {
			http.Error(w, "", http.StatusServiceUnavailable)
		}
		return
	}
	response.WriteResponse(w, http.StatusOK)
}
