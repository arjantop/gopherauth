package endpoint_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/endpoint"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/testutil"
)

type approvalDeps struct {
	serverKey       []byte
	responseTypes   map[string]*ResponseTypeMock
	handler         http.Handler
	userAuthService *service.UserAuthenticationServiceMock
	params          url.Values
	approvalParams  url.Values
}

func makeApprovalEndpointHandler() approvalDeps {
	serverKey := []byte("ServerKey")
	type1 := NewResponseTypeMock()
	type2 := NewResponseTypeMock()
	responseTypes := map[string]*ResponseTypeMock{
		"type1": type1,
		"type2": type2,
	}
	userAuthService := service.NewUserAuthenticationServiceMock()

	handler := endpoint.NewApprovalEndpointHandler(
		serverKey,
		userAuthService,
		map[string]endpoint.ResponseType{
			"type1": type1,
			"type2": type2,
		})

	params := url.Values{}
	params.Add(oauth2.ParameterResponseType, "type1")
	params.Add("param1", "value1")
	params.Add("param2", "value2")

	approvalParams := url.Values{}
	expirationTime := time.Now().Add(time.Hour).UnixNano()
	approvalParams.Add(endpoint.ApprovalParameterExpirationTime, strconv.FormatInt(expirationTime, 10))

	key := endpoint.ComputeKey(expirationTime, "SessionId", serverKey)
	mac := endpoint.ComputeMAC(params, expirationTime, "SessionId", key)

	approvalParams.Add(endpoint.ApprovalParameterSignature, base64.StdEncoding.EncodeToString(mac))

	return approvalDeps{
		serverKey:       serverKey,
		responseTypes:   responseTypes,
		handler:         handler,
		userAuthService: userAuthService,
		params:          params,
		approvalParams:  approvalParams,
	}
}

func TestApprovalEndpointIsDefinedOnlyForPostHttpMethod(t *testing.T) {
	httpMethods := []string{"GET", "HEAD", "PUT", "DELETE",
		"TRACE", "OPTIONS", "CONNECT", "PATCH"}
	for _, method := range httpMethods {
		deps := makeApprovalEndpointHandler()

		request, err := http.NewRequest(method, "", nil)
		assert.Nil(t, err)

		recorder := httptest.NewRecorder()
		deps.handler.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code,
			fmt.Sprintf("Auth endpoint should not be defined for %s", method))
	}
}

func TestApprovalEndpointUnsupportedResponseTypeIsBadRequest(t *testing.T) {
	deps := makeApprovalEndpointHandler()

	params := url.Values{}
	params.Add(oauth2.ParameterResponseType, "unsupported")
	request := testutil.NewEndpointPostRequest(t, "approval", params, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestApprovalEndpointUnauthorizedErrorIfSessionCookieIsMissing(t *testing.T) {
	deps := makeApprovalEndpointHandler()

	params := url.Values{}
	params.Add(oauth2.ParameterResponseType, "type1")
	request := testutil.NewEndpointPostRequest(t, "approval", params, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assertApprovalEndpointExpectations(t, deps)
}

func TestApprovalEndpointStatusServiceUnavaliableOnSessionValidationError(t *testing.T) {
	deps := makeApprovalEndpointHandler()

	params := url.Values{}
	params.Add(oauth2.ParameterResponseType, "type1")
	request := testutil.NewEndpointPostRequest(t, "approval", params, nil)
	sessionIdCookie := &http.Cookie{Name: "sessionid", Value: "InvalidId"}
	request.AddCookie(sessionIdCookie)

	deps.userAuthService.On("IsSessionValid", "InvalidId").Return(false, errors.New("error"))

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assertApprovalEndpointExpectations(t, deps)
}

func TestApprovalEndpointUnauthorizedErrorIfSessionIdIsInvalid(t *testing.T) {
	deps := makeApprovalEndpointHandler()

	params := url.Values{}
	params.Add(oauth2.ParameterResponseType, "type1")
	params.Add("param1", "value1")
	request := testutil.NewEndpointPostRequest(t, "approval", params, nil)
	sessionIdCookie := &http.Cookie{Name: "sessionid", Value: "InvalidId"}
	request.AddCookie(sessionIdCookie)

	deps.userAuthService.On("IsSessionValid", "InvalidId").Return(false, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assertApprovalEndpointExpectations(t, deps)
}

func TestApprovalEndpointInvalidExpirationTimeFormatBadRequest(t *testing.T) {
	makeBadRequestTest(t, func(params url.Values) url.Values {
		params[endpoint.ApprovalParameterExpirationTime] = []string{"a123"}
		return params
	})
}

func TestApprovalEndpointExpiredExpirationTimeBadRequest(t *testing.T) {
	makeBadRequestTest(t, func(params url.Values) url.Values {
		expired := strconv.FormatInt(time.Now().Add(-time.Nanosecond).UnixNano(), 10)
		params[endpoint.ApprovalParameterExpirationTime] = []string{expired}
		return params
	})
}

func TestApprovalEndpointSignatureBadEncodingBadRequest(t *testing.T) {
	makeBadRequestTest(t, func(params url.Values) url.Values {
		params[endpoint.ApprovalParameterSignature] = []string{"invalid"}
		return params
	})
}

func TestApprovalEndpointInvalidMacBadRequest(t *testing.T) {
	makeBadRequestTest(t, func(params url.Values) url.Values {
		params[endpoint.ApprovalParameterSignature] = []string{"aW52YWxpZA=="}
		return params
	})
}

func TestApprovalAfterSuccessfulValidationUserIsRedirectedToRedirectUri(t *testing.T) {
	deps := makeApprovalEndpointHandler()

	expirationTimeValue := deps.approvalParams.Get(endpoint.ApprovalParameterExpirationTime)
	expirationTime, err := strconv.ParseInt(expirationTimeValue, 10, 64)
	assert.Nil(t, err)

	key := endpoint.ComputeKey(expirationTime, "SessionId", deps.serverKey)
	mac := endpoint.ComputeMAC(deps.params, expirationTime, "SessionId", key)

	deps.approvalParams.Set(endpoint.ApprovalParameterSignature, base64.StdEncoding.EncodeToString(mac))

	request := testutil.NewEndpointPostRequest(t, "approval", deps.params, deps.approvalParams)
	sessionIdCookie := &http.Cookie{Name: "sessionid", Value: "SessionId"}
	request.AddCookie(sessionIdCookie)

	const RedirectUri = "https://example.com/callback"

	uri, err := url.Parse(RedirectUri)
	assert.Nil(t, err)
	deps.responseTypes["type1"].On("Execute", deps.params).Return(uri, nil)
	deps.userAuthService.On("IsSessionValid", "SessionId").Return(true, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusFound, recorder.Code,
		"After successful validation user must be redirected to configured redirect uri")
	assert.Equal(t, RedirectUri, recorder.Header().Get("Location"))
	assertApprovalEndpointExpectations(t, deps)
}

func makeBadRequestTest(t *testing.T, modify func(url.Values) url.Values) {
	deps := makeApprovalEndpointHandler()

	params := url.Values{}
	params.Add(oauth2.ParameterResponseType, "type1")

	request := testutil.NewEndpointPostRequest(t, "approval", params, modify(deps.approvalParams))
	sessionIdCookie := &http.Cookie{Name: "sessionid", Value: "SessionId"}
	request.AddCookie(sessionIdCookie)

	deps.userAuthService.On("IsSessionValid", "SessionId").Return(true, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code,
		"Any error in data or signature shoudl result in bad request")
	assertApprovalEndpointExpectations(t, deps)
}

func assertApprovalEndpointExpectations(t *testing.T, deps approvalDeps) {
	deps.userAuthService.Mock.AssertExpectations(t)
	for _, handler := range deps.responseTypes {
		handler.Mock.AssertExpectations(t)
	}
}
