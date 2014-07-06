package grant_type

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

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

func decodeAuthHeader(auth string) (*service.ClientCredentials, error) {
	authParts := strings.SplitN(auth, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Basic" {
		return nil, errors.New("Authorization method must be Basic")
	}
	decoded, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		return nil, err
	}
	clientCredentialsParts := strings.SplitN(string(decoded), ":", 2)
	if len(clientCredentialsParts) != 2 || clientCredentialsParts[0] == "" || clientCredentialsParts[1] == "" {
		return nil, errors.New("Invalid client credentials")
	}
	return &service.ClientCredentials{clientCredentialsParts[0], clientCredentialsParts[1]}, nil
}

func (c *PasswordController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	clientCredentials, err := decodeAuthHeader(auth)
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
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Fatalf("Json marshal failed: %s", err)
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Write(jsonResponse)
}
