package main

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/login"
	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/endpoint"
	"github.com/arjantop/gopherauth/oauth2/grant_type"
	"github.com/arjantop/gopherauth/oauth2/response_type"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/util"
)

type UserAuthenticationServiceTest struct {
	sessionMap map[string]string
}

func (m *UserAuthenticationServiceTest) IsSessionValid(sessionId string) (bool, error) {
	return m.sessionMap[sessionId] != "", nil
}

func (m *UserAuthenticationServiceTest) AuthenticateUser(user, password string) (string, error) {
	if user == "user1@example.com" && password == "pass1" {
		m.sessionMap["session1"] = "user1@example.com"
		return "session1", nil
	} else if user == "error@example.com" {
		return "", errors.New("error")
	} else {
		return "", service.CredentialsMismatch{}
	}
}

type Oauth2ServiceTest struct {
}

func (s *Oauth2ServiceTest) ValidateScope(scope []string) (*service.ScopeValidationResult, error) {
	result := service.ScopeValidationResult{
		Valid: scope,
	}
	return &result, nil
}

func (s *Oauth2ServiceTest) Password(
	c *service.ClientCredentials,
	username, password string) (*oauth2.AccessTokenResponse, error) {

	response := oauth2.AccessTokenResponse{
		AccessToken: "token",
		TokenType:   "Bearer",
		ExpiresIn:   1000,
	}
	return &response, nil
}

func (s *Oauth2ServiceTest) Code(
	clientId string, redirectURI *url.URL, scope, state string) (*oauth2.AuthorizationResponse, error) {

	response := oauth2.AuthorizationResponse{
		Code:  "code",
		State: state,
	}
	return &response, nil
}

func (s *Oauth2ServiceTest) AuthorizationCode(
	c *service.ClientCredentials, code string, redirectURI *url.URL) (*oauth2.AccessTokenResponse, error) {

	response := oauth2.AccessTokenResponse{
		AccessToken: "token",
		TokenType:   "Bearer",
		ExpiresIn:   1000,
	}
	return &response, nil
}

func main() {
	serverKey := []byte("server_key")
	tokenGenerator := service.NewCryptoTokenGenerator()

	userAuthService := &UserAuthenticationServiceTest{
		sessionMap: make(map[string]string),
	}

	loginUrl, _ := url.Parse("/login")

	oauth2Service := &Oauth2ServiceTest{}

	templateFactory := util.NewTemplateFactory("templates")

	grantTypeHandlers := map[string]endpoint.GrantType{}
	passwordHandler := grant_type.NewPasswordController(oauth2Service)
	grantTypeHandlers[oauth2.GrantTypePassword] = passwordHandler
	authCodeHandler := grant_type.NewAuthorizationCodeController(oauth2Service)
	grantTypeHandlers[oauth2.GrantTypeAuthorizationCode] = authCodeHandler

	http.Handle("/token", endpoint.NewTokenEndpointHandler(nil))

	responseTypeHandlers := map[string]endpoint.ResponseType{}
	tokenHandler := response_type.NewTokenController()
	responseTypeHandlers[oauth2.ResponseTypeToken] = tokenHandler
	codeHandler := response_type.NewCodeController(oauth2Service)
	responseTypeHandlers[oauth2.ResponseTypeCode] = codeHandler

	authEndpointController := endpoint.NewAuthEndpointHandler(
		serverKey, loginUrl, oauth2Service, userAuthService,
		templateFactory,
		responseTypeHandlers)
	http.Handle("/auth", authEndpointController)

	approvalHandler := endpoint.NewApprovalEndpointHandler(serverKey, userAuthService, responseTypeHandlers)
	http.Handle("/approval", approvalHandler)

	loginHandler := login.NewLoginHandler(serverKey, userAuthService, tokenGenerator, templateFactory)
	http.Handle("/login", loginHandler)

	http.ListenAndServe(":3000", nil)
}
