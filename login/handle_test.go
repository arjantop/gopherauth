package login_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/arjantop/gopherauth/login"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/testutil"
	"github.com/arjantop/gopherauth/util"
	"github.com/stretchr/testify/assert"
)

const redirectUrl = "https://example.com/redirect"

type loginDeps struct {
	userAuthService *service.UserAuthenticationServiceMock
	tokenGenerator  *service.TokenGeneratorMock
	templateFactory *util.TemplateFactory
	handler         http.Handler
	nonce           string
	getParams       url.Values
	postParams      url.Values
}

func makeLogin() loginDeps {
	userAuthService := service.NewUserAuthenticationServiceMock()
	tokenGenerator := service.NewTokenGeneratorMock()
	templateFactory := util.NewTemplateFactory("../templates")

	getParams := url.Values{}
	getParams.Add("continue", url.QueryEscape(redirectUrl))

	postParams := url.Values{}
	postParams.Add("email", "email@example.com")
	postParams.Add("password", "password")
	mac := hmac.New(sha256.New, []byte("ServerKey"))
	mac.Write([]byte("Nonce"))
	postParams.Add("csrf", base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	return loginDeps{
		userAuthService: userAuthService,
		tokenGenerator:  tokenGenerator,
		templateFactory: templateFactory,
		handler:         login.NewLoginHandler([]byte("ServerKey"), userAuthService, tokenGenerator, templateFactory),
		nonce:           "Nonce",
		getParams:       getParams,
		postParams:      postParams,
	}
}

func TestLoginIsDefinedOnlyForGetAndPostHttpMethods(t *testing.T) {
	httpMethods := []string{"HEAD", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"}
	for _, method := range httpMethods {
		deps := makeLogin()

		request, err := http.NewRequest(method, "", nil)
		assert.Nil(t, err)

		deps.tokenGenerator.On("Generate", uint(login.TokenSize)).Return([]byte("NewNonce"))

		recorder := httptest.NewRecorder()
		deps.handler.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code,
			fmt.Sprintf("Auth endpoint should not be defined for %s", method))
	}
}

func TestLoginFormIsDisplayed(t *testing.T) {
	deps := makeLogin()

	request := testutil.NewEndpointRequest(t, "GET", "login", nil)

	deps.tokenGenerator.On("Generate", uint(login.TokenSize)).Return([]byte("NewNonce"))

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	testutil.AssertContentTypeHtml(t, recorder)
	assert.Contains(t, recorder.Body.String(), "Sign in")
}

func TestLoginSessionIdIsSet(t *testing.T) {
	deps := makeLogin()

	request := testutil.NewEndpointPostRequest(t, "login", deps.getParams, deps.postParams)
	nonceCookie := http.Cookie{Name: "nonce", Value: deps.nonce, HttpOnly: true}
	request.AddCookie(&nonceCookie)

	deps.tokenGenerator.On("Generate", uint(login.TokenSize)).Return([]byte("NewNonce"))
	deps.userAuthService.On(
		"AuthenticateUser",
		deps.postParams.Get("email"),
		deps.postParams.Get("password")).Return("SessionId", nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.Equal(t, redirectUrl, recorder.Header().Get("Location"))
	assert.NotEmpty(t, recorder.Header().Get("Set-Cookie"), "Cookie must be set")
	deps.userAuthService.Mock.AssertExpectations(t)
}
