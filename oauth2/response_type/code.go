package response_type

import (
	"net/http"
	"net/url"
)

type CodeController struct {
}

func NewCodeController() *CodeController {
	return &CodeController{}
}

func (c *CodeController) ExtractParameters(r *http.Request) url.Values {
	return extractParameters(r)
}

func (c *CodeController) Execute(params url.Values) url.URL {
	return url.URL{}
}
