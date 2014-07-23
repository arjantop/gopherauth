package main

import (
	"errors"
	"net/http"

	"github.com/arjantop/gopherauth/login"
	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/endpoint"
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
	} else if user == "user1@example.com" {
		return "", service.CredentialsMismatch{}
	} else {
		return "", errors.New("error")
	}
}

func main() {
	serverKey := []byte("server_key")
	tokenGenerator := service.NewCryptoTokenGenerator()

	userAuthService := &UserAuthenticationServiceTest{}

	templateFactory := util.NewTemplateFactory("templates")
	http.Handle("/token", endpoint.NewTokenEndpointHandler(nil))

	responseTypeHandlers := map[string]endpoint.ResponseType{}
	tokenHandler := response_type.NewTokenController()
	responseTypeHandlers[oauth2.ResponseTypeToken] = tokenHandler
	codeHandler := response_type.NewCodeController()
	responseTypeHandlers[oauth2.ResponseTypeCode] = codeHandler

	authEndpointController := endpoint.NewAuthEndpointHandler(
		nil, nil, nil,
		templateFactory,
		responseTypeHandlers)
	http.Handle("/auth", authEndpointController)

	approvalHandler := endpoint.NewApprovalEndpointHandler(nil, nil, nil, nil)
	http.Handle("/approval", approvalHandler)

	loginHandler := login.NewLoginHandler(serverKey, userAuthService, tokenGenerator, templateFactory)
	http.Handle("/login", loginHandler)

	http.ListenAndServe(":3000", nil)
}
