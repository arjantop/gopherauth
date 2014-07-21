package response_type

import (
	"net/http"
	"net/url"
)

type TokenController struct {
}

func NewTokenController() *TokenController {
	return &TokenController{}
}

func (c *TokenController) ExtractParameters(r *http.Request) url.Values {
	return extractParameters(r)
}

func (c *TokenController) Execute(params url.Values) url.URL {
	return url.URL{}
}
