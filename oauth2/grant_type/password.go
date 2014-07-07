package grant_type

import (
	"fmt"
	"net/http"

	"github.com/arjantop/gopherauth/oauth2"
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

func NewMissingParameterError(param string) *oauth2.ErrorResponse {
	return &oauth2.ErrorResponse{
		oauth2.ErrorInvalidRequest,
		fmt.Sprintf("Missing required parameter: %s", param),
		nil,
	}
}

var InvalidClientError = oauth2.ErrorResponse{
	oauth2.ErrorInvalidClient,
	"",
	nil,
}

func (c *PasswordController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientCredentials, err := util.GetBasicAuth(r)
	if err != nil {
		InvalidClientError.WriteResponse(w, http.StatusUnauthorized)
		return
	}

	username := r.PostFormValue("username")
	if username == "" {
		NewMissingParameterError("username").WriteResponse(w, http.StatusBadRequest)
		return
	}
	password := r.PostFormValue("password")
	if password == "" {
		NewMissingParameterError("password").WriteResponse(w, http.StatusBadRequest)
		return
	}

	response, err := c.oauth2Service.PasswordFlow(clientCredentials, username, password)
	if err != nil {
		if response, ok := err.(*oauth2.ErrorResponse); ok {
			response.WriteResponse(w, http.StatusBadRequest)
		} else {
			http.Error(w, "", http.StatusInternalServerError)
		}
		return
	}

	response.WriteResponse(w, http.StatusOK)
}
