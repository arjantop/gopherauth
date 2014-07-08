package grant_type

import (
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/helpers"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/util"
)

type PasswordController struct {
	oauth2Service service.Oauth2Service
}

func NewPasswordController(oauth2Service service.Oauth2Service) *PasswordController {
	return &PasswordController{
		oauth2Service: oauth2Service,
	}
}

func (c *PasswordController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientCredentials, err := util.GetBasicAuth(r)
	if err != nil {
		response := helpers.NewMissingClientCredentialsError()
		response.WriteResponse(w, http.StatusUnauthorized)
		return
	}

	username := r.PostFormValue(oauth2.ParameterUsername)
	password := r.PostFormValue(oauth2.ParameterPassword)

	params := url.Values{}
	params.Add(oauth2.ParameterUsername, username)
	params.Add(oauth2.ParameterPassword, password)

	valid := helpers.ValidateParameters(params, w)
	if !valid {
		return
	}

	response, err := c.oauth2Service.PasswordFlow(clientCredentials, username, password)
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
