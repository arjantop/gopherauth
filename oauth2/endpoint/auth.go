package endpoint

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/helpers"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/util"
)

const expiresIn = 2 * time.Hour

type Scope struct {
	Description string
}

type ApprovalPrompt struct {
	Scopes         []*Scope
	ExpirationTime int64
	Signature      string
	Parameters     template.URL
}

type ResponseType interface {
	ExtractParameters(r *http.Request) url.Values
	Execute(params url.Values) (*url.URL, error)
}

type authEndpointHandler struct {
	serverKey       []byte
	loginUrl        *url.URL
	oauth2Service   service.Oauth2Service
	userAuthService service.UserAuthenticationService
	templateFactory *util.TemplateFactory
	handlers        map[string]ResponseType
}

func NewAuthEndpointHandler(
	serverKey []byte,
	loginUrl *url.URL,
	oauth2Service service.Oauth2Service,
	userAuthService service.UserAuthenticationService,
	templateFactory *util.TemplateFactory,
	handlers map[string]ResponseType) http.Handler {

	handler := &authEndpointHandler{
		serverKey:       serverKey,
		loginUrl:        loginUrl,
		oauth2Service:   oauth2Service,
		userAuthService: userAuthService,
		templateFactory: templateFactory,
		handlers:        handlers,
	}
	noCachingMiddleware := util.NoCachingMiddleware(handler)
	return noCachingMiddleware
}

func (h *authEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	responseType := query.Get(oauth2.ParameterResponseType)

	if handler, ok := h.handlers[responseType]; ok {
		params := handler.ExtractParameters(r)
		for param, val := range params {
			if val[0] == "" {
				response := helpers.NewMissingParameterError(param, nil)
				helpers.RenderError(w, h.templateFactory, response)
				return
			}
		}
		params.Add(oauth2.ParameterResponseType, responseType)

		scope := oauth2.ParseScope(params.Get(oauth2.ParameterScope))

		validationResult, err := h.oauth2Service.ValidateScope(scope)
		if err != nil {
			util.RenderHTTPError(w, h.templateFactory, util.HTTPErrorServiceUnavaliable())
			return
		}
		if !validationResult.IsValid() {
			response := &oauth2.ErrorResponse{
				ErrorCode:   oauth2.ErrorInvalidScope,
				Description: "Some requested scopes were invalid",
				Uri:         nil,
			}
			helpers.RenderError(w, h.templateFactory, response)
			return
		}

		sessionId, err := r.Cookie("sessionid")
		if err != nil {
			util.RedirectToLogin(w, r, *h.loginUrl, r.URL)
			return
		}
		isAuthenticated, err := h.userAuthService.IsSessionValid(sessionId.Value)
		if err != nil {
			util.RenderHTTPError(w, h.templateFactory, util.HTTPErrorServiceUnavaliable())
			return
		}
		if !isAuthenticated {
			util.RedirectToLogin(w, r, *h.loginUrl, r.URL)
			return
		}
		expirationTime := time.Now().Add(expiresIn).UnixNano()
		userKey := ComputeKey(expirationTime, sessionId.Value, h.serverKey)
		sig := ComputeMAC(params, expirationTime, sessionId.Value, userKey)
		data := ApprovalPrompt{
			Scopes:         []*Scope{&Scope{Description: "Scope description"}},
			ExpirationTime: expirationTime,
			Signature:      base64.StdEncoding.EncodeToString(sig),
			Parameters:     template.URL(params.Encode()),
		}
		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		// TODO: Finish implementing approval prompt
		h.templateFactory.ExecuteTemplate(w, "approval_prompt", &data)
	} else {
		var description string
		if responseType == "" {
			description = fmt.Sprintf("Required parameter is missing: %s", oauth2.ParameterResponseType)
		} else {
			description = fmt.Sprintf("Invalid response_type: %s", responseType)
		}
		helpers.RenderError(w, h.templateFactory, &oauth2.ErrorResponse{
			ErrorCode:   oauth2.ErrorInvalidRequest,
			Description: description,
			Uri:         nil})
	}
}
