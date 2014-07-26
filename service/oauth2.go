package service

import (
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
)

type ClientCredentials struct {
	Id     string
	Secret string
}

type ScopeValidationResult struct {
	Valid   []string
	Invalid []string
}

func (s *ScopeValidationResult) IsValid() bool {
	return len(s.Invalid) == 0
}

type Oauth2Service interface {
	ValidateScope(scope []string) (*ScopeValidationResult, error)

	Password(c *ClientCredentials, username, password string) (*oauth2.AccessTokenResponse, error)

	Code(clientId string, redirectURI *url.URL, scope, state string) (*oauth2.AuthorizationResponse, error)

	AuthorizationCode(c *ClientCredentials, code string, redirectURI *url.URL) (*oauth2.AccessTokenResponse, error)
}
