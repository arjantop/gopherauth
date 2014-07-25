package endpoint

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/helpers"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/util"
)

type GrantType interface {
	ExtractParameters(r *http.Request) url.Values
	Execute(clientCredentials *service.ClientCredentials, params url.Values) (*oauth2.AccessTokenResponse, error)
}

type tokenEndpointHandler struct {
	handlers map[string]GrantType
}

func NewTokenEndpointHandler(handlers map[string]GrantType) http.Handler {
	handler := &tokenEndpointHandler{
		handlers: handlers,
	}
	authMiddleware := util.ClientCredentialsFromFormDataToHeaderMiddleware(handler)
	noCachingMiddleware := util.NoCachingMiddleware(authMiddleware)
	return noCachingMiddleware
}

func NewUnsupportedGrantTypeError(gt string) *oauth2.ErrorResponse {
	return &oauth2.ErrorResponse{
		oauth2.ErrorUnsupportedGrantType,
		fmt.Sprintf("Unsupported grant type: %s", gt),
		nil,
	}
}

func (h *tokenEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	clientCredentials, err := util.GetBasicAuth(r)
	if err != nil {
		response := helpers.NewMissingClientCredentialsError()
		response.WriteResponse(w, http.StatusUnauthorized)
		return
	}

	grantType := r.PostFormValue(oauth2.ParameterGrantType)
	if handler, ok := h.handlers[grantType]; ok {
		params := handler.ExtractParameters(r)
		valid := helpers.ValidateParameters(params, w)
		if !valid {
			return
		}

		response, err := handler.Execute(clientCredentials, params)
		if err != nil {
			if response, ok := err.(*oauth2.ErrorResponse); ok {
				response.WriteResponse(w, http.StatusBadRequest)
			} else {
				http.Error(w, "", http.StatusServiceUnavailable)
			}
			return
		}
		response.WriteResponse(w, http.StatusOK)
	} else {
		NewUnsupportedGrantTypeError(grantType).WriteResponse(w, http.StatusBadRequest)
	}
}
