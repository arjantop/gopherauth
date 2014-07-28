package service

import (
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
)

type ClientCredentials struct {
	Id     string
	Secret string
}

type ScopeInfo struct {
	Description string
	MoreInfo    string
	MoreURI     *url.URL
}

type Oauth2Service interface {
	ValidateRequest(clientID, scope, redirectURI string) error

	Password(c *ClientCredentials, username, password string) (*oauth2.AccessTokenResponse, error)

	Code(clientId string, redirectURI *url.URL, scope, state string) (*oauth2.AuthorizationResponse, error)

	AuthorizationCode(c *ClientCredentials, code string, redirectURI *url.URL) (*oauth2.AccessTokenResponse, error)

	ScopeInfo(scope, locale string) ([]*ScopeInfo, error)
}
