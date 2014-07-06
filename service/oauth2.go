package service

import "github.com/arjantop/gopherauth/oauth2"

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
	PasswordFlow(c *ClientCredentials, username, password string) (*oauth2.AccessTokenResponse, error)
	ValidateScope(scope []string) (*ScopeValidationResult, error)
}
