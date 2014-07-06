package endpoint

import (
	"fmt"
	"net/http"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/helpers"
	"github.com/arjantop/gopherauth/util"
)

type authEndpointHandler struct {
	grantTypeCodeCtrl http.Handler
	templateFactory   *util.TemplateFactory
}

func NewAuthEndpointHandler(
	grantTypeCodeCtrl http.Handler,
	templateFactory *util.TemplateFactory) http.Handler {
	handler := &authEndpointHandler{
		grantTypeCodeCtrl: grantTypeCodeCtrl,
		templateFactory:   templateFactory}
	noCachingMiddleware := util.NoCachingMiddleware(handler)
	return noCachingMiddleware
}

func (t *authEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	responseType := query.Get(oauth2.ParameterResponseType)
	switch responseType {
	case oauth2.ResponseTypeCode:
		t.grantTypeCodeCtrl.ServeHTTP(w, r)
	default:
		var description string
		if responseType == "" {
			description = fmt.Sprintf("Required parameter is missing: %s", oauth2.ParameterResponseType)
		} else {
			description = fmt.Sprintf("Invalid response_type: %s", responseType)
		}
		helpers.RenderError(w, t.templateFactory, &oauth2.ErrorResponse{
			ErrorCode:   oauth2.ErrorInvalidRequest,
			Description: description,
			Uri:         nil})
	}
}
