package response_type

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/service"
)

type CodeController struct {
	oauth2Service service.Oauth2Service
}

func NewCodeController(oauth2Service service.Oauth2Service) *CodeController {
	return &CodeController{
		oauth2Service: oauth2Service,
	}
}

func (c *CodeController) ExtractParameters(r *http.Request) url.Values {
	return extractParameters(r)
}

func (c *CodeController) Execute(params url.Values) (*url.URL, error) {
	clientId := params.Get(oauth2.ParameterClientId)
	redirectURIString := params.Get(oauth2.ParameterRedirectUri)
	redirectURI, err := url.Parse(redirectURIString)
	if err != nil {
		return nil, err
	}
	scope := params.Get(oauth2.ParameterScope)
	state := params.Get(oauth2.ParameterState)
	response, err := c.oauth2Service.Code(clientId, redirectURI, scope, state)
	if err != nil {
		return nil, err
	}
	if redirectURI.RawQuery == "" {
		redirectURI.RawQuery = response.Encode()
	} else {
		parts := []string{redirectURI.RawQuery, response.Encode()}
		redirectURI.RawQuery = strings.Join(parts, "&")
	}
	return redirectURI, nil
}
