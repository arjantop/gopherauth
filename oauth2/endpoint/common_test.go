package endpoint_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func AssertIsRedirectedToLogin(t *testing.T, recorder *httptest.ResponseRecorder, returnTo *url.URL) {
	assert.Equal(t, http.StatusFound, recorder.Code, "Response code should be 302 Found")
	redirectUrl, err := url.Parse(recorder.Header().Get("Location"))
	assert.Nil(t, err)
	assert.True(t, redirectUrl.IsAbs())
	assert.NotEmpty(t, redirectUrl.Query().Get("continue"),
		"continue parameter must be present: %s", redirectUrl.String())
}
