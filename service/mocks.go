package service

import (
	"net/url"

	"github.com/stretchr/testify/mock"

	"github.com/arjantop/gopherauth/oauth2"
)

type UserAuthenticationServiceMock struct {
	mock.Mock
}

func (m *UserAuthenticationServiceMock) IsSessionValid(sessionId string) (bool, error) {
	args := m.Mock.Called(sessionId)
	return args.Bool(0), args.Error(1)
}

func (m *UserAuthenticationServiceMock) AuthenticateUser(user, password string) (string, error) {
	args := m.Mock.Called(user, password)
	return args.String(0), args.Error(1)
}

func NewUserAuthenticationServiceMock() *UserAuthenticationServiceMock {
	return &UserAuthenticationServiceMock{}
}

type Oauth2ServiceMock struct {
	mock.Mock
}

func (s *Oauth2ServiceMock) ValidateScope(scope []string) (*ScopeValidationResult, error) {
	args := s.Mock.Called(scope)
	tokenResponse, _ := args.Get(0).(*ScopeValidationResult)
	return tokenResponse, args.Error(1)
}

func (s *Oauth2ServiceMock) PasswordFlow(c *ClientCredentials, username, password string) (*oauth2.AccessTokenResponse, error) {
	args := s.Mock.Called(c, username, password)
	tokenResponse, _ := args.Get(0).(*oauth2.AccessTokenResponse)
	return tokenResponse, args.Error(1)
}

func (s *Oauth2ServiceMock) Code(
	clientId string, redirectURI *url.URL, scope, state string) (*oauth2.AuthorizationResponse, error) {

	args := s.Mock.Called(clientId, redirectURI, scope, state)
	response, _ := args.Get(0).(*oauth2.AuthorizationResponse)
	return response, args.Error(1)
}

func (s *Oauth2ServiceMock) AuthorizationCode(
	c *ClientCredentials, code, redirect_uri string) (*oauth2.AccessTokenResponse, error) {

	args := s.Mock.Called(c, code, redirect_uri)
	tokenResponse, _ := args.Get(0).(*oauth2.AccessTokenResponse)
	return tokenResponse, args.Error(1)
}

func NewOauth2ServiceMock() *Oauth2ServiceMock {
	return &Oauth2ServiceMock{}
}

type TokenGeneratorMock struct {
	mock.Mock
}

func (t *TokenGeneratorMock) Generate(n uint) []byte {
	args := t.Mock.Called(n)
	token, ok := args.Get(0).([]byte)
	if !ok {
		panic("Argument 0 not of correct type")
	}
	return token
}

func NewTokenGeneratorMock() *TokenGeneratorMock {
	return &TokenGeneratorMock{}
}
