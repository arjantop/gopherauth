package service

import (
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

func (s *Oauth2ServiceMock) AuthorizationCode(c *ClientCredentials, code, redirect_uri string) (*oauth2.AccessTokenResponse, error) {
	args := s.Mock.Called(c, code, redirect_uri)
	tokenResponse, _ := args.Get(0).(*oauth2.AccessTokenResponse)
	return tokenResponse, args.Error(1)
}

func NewOauth2ServiceMock() *Oauth2ServiceMock {
	return &Oauth2ServiceMock{}
}
