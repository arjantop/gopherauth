package response_type

import (
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/helpers"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/util"
)

type Scope struct {
	Description string
}

type ApprovalPrompt struct {
	Scopes []*Scope
}

type CodeController struct {
	loginUrl        *url.URL
	userAuthService service.UserAuthenticationService
	oauth2Service   service.Oauth2Service
	templateFactory *util.TemplateFactory
}

func NewCodeController(
	loginUrl *url.URL,
	userAuthService service.UserAuthenticationService,
	oauth2Service service.Oauth2Service,
	templateFactory *util.TemplateFactory) *CodeController {
	return &CodeController{
		loginUrl:        loginUrl,
		userAuthService: userAuthService,
		oauth2Service:   oauth2Service,
		templateFactory: templateFactory}
}

func (c *CodeController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientId := query.Get(oauth2.ParameterClientId)
	redirectUri := query.Get(oauth2.ParameterRedirectUri)
	state := query.Get(oauth2.ParameterState)
	scopeString := query.Get(oauth2.ParameterScope)

	params := url.Values{}
	params.Add(oauth2.ParameterClientId, clientId)
	params.Add(oauth2.ParameterRedirectUri, redirectUri)
	params.Add(oauth2.ParameterState, state)
	params.Add(oauth2.ParameterScope, scopeString)
	for param, val := range params {
		if val[0] == "" {
			response := helpers.NewMissingParameterError(param, nil)
			helpers.RenderError(w, c.templateFactory, response)
			return
		}
	}
	params.Add(oauth2.ParameterResponseType, oauth2.ResponseTypeCode)

	scope := oauth2.ParseScope(scopeString)

	validationResult, err := c.oauth2Service.ValidateScope(scope)
	if err != nil {
		panic("ValidateScope error")
	}
	if !validationResult.IsValid() {
		response := &oauth2.ErrorResponse{
			ErrorCode:   oauth2.ErrorInvalidScope,
			Description: "Some requested scopes were invalid",
			Uri:         nil,
		}
		helpers.RenderError(w, c.templateFactory, response)
		return
	}

	sessionId, err := r.Cookie("sessionid")
	if err != nil {
		c.redirectToLoginUrl(w, r, &params)
		return
	}
	isAuthenticated, err := c.userAuthService.IsSessionValid(sessionId.Value)
	if !isAuthenticated {
		c.redirectToLoginUrl(w, r, &params)
		return
	}
	if err != nil {
		panic("IsSessionValid error")
	}
	data := ApprovalPrompt{Scopes: []*Scope{&Scope{Description: "Scope description"}}}
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	// TODO: Finish implementing approval prompt
	c.templateFactory.ExecuteTemplate(w, "approval_prompt", &data)
}

func (c *CodeController) redirectToLoginUrl(w http.ResponseWriter, r *http.Request, params *url.Values) {
	redirectUrl := c.loginUrl.String() + "?parameters=" + url.QueryEscape(params.Encode())
	http.Redirect(w, r, redirectUrl, http.StatusFound)
}
