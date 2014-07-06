package response_type_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/response_type"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/util"
)

const (
	endpointUrl     = "http://example.com/auth"
	loginUrl        = "http://example.com/login"
	contentTypeHtml = "text/html; charset=utf-8"
)

var templateFactory = util.NewTemplateFactory("../../templates")

type deps struct {
	userAuthService *service.UserAuthenticationServiceMock
	oauth2Service   *service.Oauth2ServiceMock
	params          url.Values
	controller      *response_type.CodeController
}

func makeAuthCodeController() deps {
	userAuthService := service.NewUserAuthenticationServiceMock()
	oauth2Service := service.NewOauth2ServiceMock()
	params := makeAuthCodeRequestParameters()
	return deps{
		userAuthService: userAuthService,
		oauth2Service:   oauth2Service,
		params:          params,
		controller: response_type.NewCodeController(
			makeLoginUrl(),
			userAuthService,
			oauth2Service,
			templateFactory),
	}
}

func (d *deps) getScope() []string {
	return oauth2.ParseScope(d.params.Get("scope"))
}

func makeAuthCodeRequestParameters() url.Values {
	return map[string][]string{
		"response_type": []string{"code"},
		"client_id":     []string{"client_id"},
		"redirect_uri":  []string{"http://domain.com"},
		"scope":         []string{"scope1 scope2"},
		"state":         []string{"state"},
	}
}

func makeLoginUrl() *url.URL {
	url, _ := url.Parse(loginUrl)
	return url
}

func assertBadRequestHtmlOutput(t *testing.T, recorder *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusBadRequest, recorder.Code, "Response code should be 400 Bad Request")
	assert.Equal(t, contentTypeHtml, recorder.Header().Get("Content-Type"), "Response type should be html")
}

func assertErrorIsDisplayedIfRequiredParameterIsMissing(t *testing.T, param string) {
	deps := makeAuthCodeController()
	deps.params.Del(param)
	request, err := http.NewRequest("GET", endpointUrl+"?"+deps.params.Encode(), nil)
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assertBadRequestHtmlOutput(t, recorder)
	assert.Contains(t, recorder.Body.String(), "invalid_request", "HTML output should contain error name")
	assert.Contains(t, recorder.Body.String(), param,
		fmt.Sprintf("HTML output should contain parameter name: %s", param))
}

func TestErrorIsDisplayedIfClientIdIsMissing(t *testing.T) {
	assertErrorIsDisplayedIfRequiredParameterIsMissing(t, "client_id")
}

func TestErrorIsDisplayedIfRedirectUriIsMissing(t *testing.T) {
	assertErrorIsDisplayedIfRequiredParameterIsMissing(t, "redirect_uri")
}

func TestErrorIsDisplayedIfScopeIsMissing(t *testing.T) {
	assertErrorIsDisplayedIfRequiredParameterIsMissing(t, "scope")
}

func TestErrorIsDisplayedIfStateIsMissing(t *testing.T) {
	assertErrorIsDisplayedIfRequiredParameterIsMissing(t, "state")
}

func TestErrorIsDisplayedIfSomeRequestedScopesAreInvalid(t *testing.T) {
	deps := makeAuthCodeController()
	request, err := http.NewRequest("GET", endpointUrl+"?"+deps.params.Encode(), nil)
	assert.Nil(t, err)

	scope := deps.getScope()
	deps.oauth2Service.On("ValidateScope", scope).Return(&service.ScopeValidationResult{
		Valid:   []string{scope[0]},
		Invalid: []string{scope[1]}}, nil)

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assertBadRequestHtmlOutput(t, recorder)
	assert.Contains(t, recorder.Body.String(), "invalid_scope", "HTML output should contain error name")
}

func assertIsRedirectedToLogin(t *testing.T, recorder *httptest.ResponseRecorder, params *url.Values) {
	assert.Equal(t, http.StatusFound, recorder.Code, "Response code should be 302 Found")
	assert.Equal(t, loginUrl+"?parameters="+url.QueryEscape(params.Encode()),
		recorder.Header().Get("Location"))
}

func TestNotAuthenticatedUserWithNoSessionCookieIsRedirectedToLogin(t *testing.T) {
	deps := makeAuthCodeController()
	request, err := http.NewRequest("GET", endpointUrl+"?"+deps.params.Encode(), nil)
	assert.Nil(t, err)

	scope := strings.Split(deps.params.Get("scope"), " ")
	deps.oauth2Service.On("ValidateScope", scope).Return(
		&service.ScopeValidationResult{Valid: scope}, nil)

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assertIsRedirectedToLogin(t, recorder, &deps.params)
}

func TestNotAuthenticatedUserWithInvalidSessionIdIsRedirectedToLogin(t *testing.T) {
	deps := makeAuthCodeController()
	request, err := http.NewRequest("GET", endpointUrl+"?"+deps.params.Encode(), nil)
	sessionIdCookie := &http.Cookie{Name: "sessionid", Value: "invalid_id"}
	request.AddCookie(sessionIdCookie)
	assert.Nil(t, err)

	deps.userAuthService.On("IsSessionValid", "invalid_id").Return(false, nil)
	scope := deps.getScope()
	deps.oauth2Service.On("ValidateScope", scope).Return(
		&service.ScopeValidationResult{Valid: scope}, nil)

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assertIsRedirectedToLogin(t, recorder, &deps.params)
}

func TestAuthenticatedUserIsPresentedWithApprovalPrompt(t *testing.T) {
	deps := makeAuthCodeController()
	request, err := http.NewRequest("GET", endpointUrl+"?"+deps.params.Encode(), nil)
	sessionIdCookie := &http.Cookie{Name: "sessionid", Value: "session_id"}
	request.AddCookie(sessionIdCookie)
	assert.Nil(t, err)

	deps.userAuthService.On("IsSessionValid", "session_id").Return(true, nil)
	scope := deps.getScope()
	deps.oauth2Service.On("ValidateScope", scope).Return(
		&service.ScopeValidationResult{Valid: scope}, nil)

	recorder := httptest.NewRecorder()
	deps.controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code, "Response code should be 200 OK")
	assert.Equal(t, contentTypeHtml, recorder.Header().Get("Content-Type"), "Response type should be html")
	assert.Contains(t, recorder.Body.String(), "Scope description")
}
