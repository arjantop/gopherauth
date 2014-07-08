package testutil

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const serviceUrl = "https://example.com"

func NewEndpointRequest(t *testing.T, method, endpoint string, params url.Values) *http.Request {
	if method != "GET" && method != "POST" {
		panic("Only GET and POST allowed")
	}
	getParams := ""
	if method == "GET" {
		getParams = "?" + params.Encode()
	}
	var postParams io.Reader
	if method == "POST" {
		postParams = strings.NewReader(params.Encode())
	}
	url := serviceUrl + "/" + endpoint + getParams
	request, err := http.NewRequest(method, url, postParams)
	assert.Nil(t, err)
	if method == "POST" {
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}
	return request
}
