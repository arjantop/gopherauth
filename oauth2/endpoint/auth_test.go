package endpoint_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/endpoint"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/testutil"
	"github.com/arjantop/gopherauth/util"
)

const (
	contentTypeHtml = "text/html; charset=utf-8"
	templateRoot    = "../../templates"
	LoginUrl        = "https://example.com/login"
	clientURI       = "https://client.example.com/cb"
)

func makeLoginUrl() *url.URL {
	url, _ := url.Parse(LoginUrl)
	return url
}

type ResponseTypeMock struct {
	mock.Mock
}

func (m *ResponseTypeMock) ExtractParameters(r *http.Request) url.Values {
	args := m.Mock.Called(r)
	params, _ := args.Get(0).(url.Values)
	return params
}

func (m *ResponseTypeMock) Execute(params url.Values) (*url.URL, error) {
	args := m.Mock.Called(params)
	url, ok := args.Get(0).(*url.URL)
	if !ok {
		panic("Return value is not of correct type")
	}
	return url, args.Error(1)
}

func NewResponseTypeMock() *ResponseTypeMock {
	return &ResponseTypeMock{}
}

type authDeps struct {
	params          url.Values
	responseTypes   map[string]*ResponseTypeMock
	handler         http.Handler
	oauth2Service   *service.Oauth2ServiceMock
	userAuthService *service.UserAuthenticationServiceMock
	templateFactory *util.TemplateFactory
}

func makeAuthEndpointHandler() authDeps {
	params := url.Values{}
	params.Add("response_type", "type1")
	params.Add("client_id", "client_id")
	params.Add("scope", "scope1 scope2")
	params.Add("redirect_uri", clientURI)

	type1 := NewResponseTypeMock()
	type2 := NewResponseTypeMock()
	responseTypes := map[string]*ResponseTypeMock{
		"type1": type1,
		"type2": type2,
	}
	oauth2Service := service.NewOauth2ServiceMock()
	userAuthService := service.NewUserAuthenticationServiceMock()
	handler := endpoint.NewAuthEndpointHandler(
		[]byte("ServerKey"),
		makeLoginUrl(),
		oauth2Service,
		userAuthService,
		util.NewTemplateFactory(templateRoot),
		map[string]endpoint.ResponseType{
			"type1": type1,
			"type2": type2,
		})
	return authDeps{
		params:          params,
		responseTypes:   responseTypes,
		handler:         handler,
		oauth2Service:   oauth2Service,
		userAuthService: userAuthService,
	}
}

func TestAuthEndpointIsDefinedOnlyForGetHttpMethod(t *testing.T) {
	httpMethods := []string{"POST", "HEAD", "PUT", "DELETE",
		"TRACE", "OPTIONS", "CONNECT", "PATCH"}
	for _, method := range httpMethods {
		deps := makeAuthEndpointHandler()

		request, err := http.NewRequest(method, "", nil)
		assert.Nil(t, err)

		recorder := httptest.NewRecorder()
		deps.handler.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code,
			fmt.Sprintf("Auth endpoint should not be defined for %s", method))
	}
}

func TestAuthEndpointCorrectResponseTypeControllerIsUsedForParameterParsing(t *testing.T) {
	deps := makeAuthEndpointHandler()

	for responseType, handler := range deps.responseTypes {
		params := url.Values{}
		params.Add("response_type", responseType)
		request := testutil.NewEndpointRequest(t, "GET", "auth", params)
		handler.On("ExtractParameters", request).Return(params)
		deps.oauth2Service.On("ValidateRequest", "", "", "").Return(errors.New("error"))

		recorder := httptest.NewRecorder()
		deps.handler.ServeHTTP(recorder, request)
		assertAuthEndpointExpectations(t, deps)
	}
}

func TestAuthEndpointErrorIsDisplayedIfParsedParameterIsEmpty(t *testing.T) {
	deps := makeAuthEndpointHandler()

	params := url.Values{}
	params.Add("response_type", "type1")
	params.Add("param1", "value1")
	request := testutil.NewEndpointRequest(t, "GET", "auth", params)
	params.Add("param2", "")
	deps.responseTypes["type1"].On("ExtractParameters", request).Return(params)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assertIsBadRequest(t, recorder)
	assert.Contains(t, recorder.Body.String(), "invalid_request", "HTML output should contain error name")
	assert.Contains(t, recorder.Body.String(), "param2",
		fmt.Sprintf("HTML output should contain parameter name: param2"))
	assertAuthEndpointExpectations(t, deps)
}

func TestErrorIsDisplayedIfResponseTypeIsInvalid(t *testing.T) {
	deps := makeAuthEndpointHandler()

	params := url.Values{}
	params.Add("response_type", "invalid")
	request := testutil.NewEndpointRequest(t, "GET", "auth", params)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assertIsBadRequest(t, recorder)
	assert.Contains(t, recorder.Body.String(), "response_type")
}

func TestErrorIsDisplayedIfResponseTypeIsMissing(t *testing.T) {
	deps := makeAuthEndpointHandler()

	params := url.Values{}
	request := testutil.NewEndpointRequest(t, "GET", "auth", params)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assertIsBadRequest(t, recorder)
	assert.Contains(t, recorder.Body.String(), "missing")
	assert.Contains(t, recorder.Body.String(), "response_type")
}

func TestErrorIsDisaplayedIfOauth2ServiceErrorOccurs(t *testing.T) {
	deps := makeAuthEndpointHandler()

	params := url.Values{}
	params.Add("response_type", "type1")
	request := testutil.NewEndpointRequest(t, "GET", "auth", params)

	deps.responseTypes["type1"].On("ExtractParameters", request).Return(params)
	deps.oauth2Service.On("ValidateRequest", "", "", "").Return(errors.New("error"))

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)

	assertAuthEndpointExpectations(t, deps)
}

func TestErrorisDisplayedIfRequestValidationFails(t *testing.T) {
	deps := makeAuthEndpointHandler()

	request := testutil.NewEndpointRequest(t, "GET", "auth", deps.params)

	deps.responseTypes["type1"].On("ExtractParameters", request).Return(deps.params)
	deps.oauth2Service.On(
		"ValidateRequest", "client_id", "scope1 scope2", clientURI).Return(&oauth2.ErrorResponse{
		ErrorCode: oauth2.ErrorInvalidScope,
	})

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assertIsBadRequest(t, recorder)
	assert.Contains(t, recorder.Body.String(), "invalid_scope")

	assertAuthEndpointExpectations(t, deps)
}

func TestUserIsRedirectedToLoginIfSessionCookieIsNotFound(t *testing.T) {
	deps := makeAuthEndpointHandler()

	request := testutil.NewEndpointRequest(t, "GET", "auth", deps.params)

	deps.responseTypes["type1"].On("ExtractParameters", request).Return(deps.params)
	deps.oauth2Service.On(
		"ValidateRequest", "client_id", "scope1 scope2", clientURI).Return(nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	AssertIsRedirectedToLogin(t, recorder, request.URL)
	assertAuthEndpointExpectations(t, deps)
}

func TestUserIsRedirectedToLoginIfSessionValueIsInvalid(t *testing.T) {
	deps := makeAuthEndpointHandler()

	request := testutil.NewEndpointRequest(t, "GET", "auth", deps.params)
	sessionIdCookie := &http.Cookie{Name: "sessionid", Value: "invalid_id"}
	request.AddCookie(sessionIdCookie)

	deps.responseTypes["type1"].On("ExtractParameters", request).Return(deps.params)
	deps.oauth2Service.On(
		"ValidateRequest", "client_id", "scope1 scope2", clientURI).Return(nil)
	deps.userAuthService.On("IsSessionValid", "invalid_id").Return(false, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	AssertIsRedirectedToLogin(t, recorder, request.URL)
	assertAuthEndpointExpectations(t, deps)
}

func TestErrorIsDisaplyedIfUserAuthServiceErrorOccurs(t *testing.T) {
	deps := makeAuthEndpointHandler()

	request := testutil.NewEndpointRequest(t, "GET", "auth", deps.params)
	sessionIdCookie := &http.Cookie{Name: "sessionid", Value: "valid_id"}
	request.AddCookie(sessionIdCookie)

	deps.responseTypes["type1"].On("ExtractParameters", request).Return(deps.params)
	deps.oauth2Service.On(
		"ValidateRequest", "client_id", "scope1 scope2", clientURI).Return(nil)
	deps.userAuthService.On("IsSessionValid", "valid_id").Return(false, errors.New("error"))

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assertAuthEndpointExpectations(t, deps)
}

func TestAuthenticatedUserIsPresentedWithApprovalPrompt(t *testing.T) {
	deps := makeAuthEndpointHandler()

	request := testutil.NewEndpointRequest(t, "GET", "auth", deps.params)
	sessionIdCookie := &http.Cookie{Name: "sessionid", Value: "valid_id"}
	request.AddCookie(sessionIdCookie)

	deps.responseTypes["type1"].On("ExtractParameters", request).Return(deps.params)
	deps.oauth2Service.On(
		"ValidateRequest", "client_id", "scope1 scope2", clientURI).Return(nil)
	deps.userAuthService.On("IsSessionValid", "valid_id").Return(true, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	//TODO incomplete implementation
	assert.Equal(t, http.StatusOK, recorder.Code, "Response code should be 200 OK")
	assert.Equal(t, contentTypeHtml, recorder.Header().Get("Content-Type"), "Response type should be html")
	assertAuthEndpointExpectations(t, deps)
}

func TestNoCacheHeadersAreSet(t *testing.T) {
	deps := makeAuthEndpointHandler()

	params := url.Values{}
	request := testutil.NewEndpointRequest(t, "GET", "auth", params)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, recorder.Header().Get("Cache-Control"), "no-store", "Cache-Control header should be set")
	assert.Equal(t, recorder.Header().Get("Pragma"), "no-cache", "Pragma header should be set")
}

func assertAuthEndpointExpectations(t *testing.T, deps authDeps) {
	deps.oauth2Service.Mock.AssertExpectations(t)
	deps.userAuthService.Mock.AssertExpectations(t)
	for _, handler := range deps.responseTypes {
		handler.Mock.AssertExpectations(t)
	}
}

func assertIsBadRequest(t *testing.T, recorder *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusBadRequest, recorder.Code, "Response code should be 400 Bad Request")
	assert.Equal(t, contentTypeHtml, recorder.Header().Get("Content-Type"), "Response type should be html")
}
