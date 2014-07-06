package testutil

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func AssertContentTypeJson(t *testing.T, recorder *httptest.ResponseRecorder) {
	assert.Equal(t, recorder.Header().Get("Content-Type"), "application/json;charset=UTF-8",
		"Content type should be json")
}
