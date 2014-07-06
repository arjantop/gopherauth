package endpoint

import (
	"fmt"
	"net/http"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/util"
)

type tokenEndpointHandler struct {
	responseTypePasswordCtrl http.Handler
}

func NewTokenEndpointHandler(responseTypePasswordCtrl http.Handler) http.Handler {
	handler := &tokenEndpointHandler{
		responseTypePasswordCtrl: responseTypePasswordCtrl,
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

	grantType := r.FormValue(oauth2.ParameterGrantType)
	switch grantType {
	case oauth2.GrantTypePassword:
		h.responseTypePasswordCtrl.ServeHTTP(w, r)
	default:
		NewUnsupportedGrantTypeError(grantType).WriteResponse(w, http.StatusBadRequest)
	}
}
