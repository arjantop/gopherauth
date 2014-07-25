package grant_type_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/testutil"
)

//TODO remove
func assertMissingParameter(t *testing.T, controller http.Handler, params url.Values, name string) {
	params.Del(name)
	request := testutil.NewEndpointRequest(t, "POST", "token", params)
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)
	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)
	assert.Equal(t, 2, len(jsonMap))
	assert.Equal(t, oauth2.ErrorInvalidRequest, jsonMap["error"])
	assert.NotEmpty(t, jsonMap["error_description"])
}

func assertResponseValid(
	t *testing.T,
	tokenResponse *oauth2.AccessTokenResponse,
	recorder *httptest.ResponseRecorder) {

	assert.Equal(t, http.StatusOK, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)

	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)

	assert.Equal(t, 3, len(jsonMap))
	assert.Equal(t, tokenResponse.AccessToken, jsonMap["access_token"])
	assert.Equal(t, tokenResponse.TokenType, jsonMap["token_type"])
	assert.Equal(t, tokenResponse.ExpiresIn, jsonMap["expires_in"])
}

func assertMissingCredentialsError(t *testing.T, controller http.Handler, params url.Values) {
	request := testutil.NewEndpointRequest(t, "POST", "token", params)

	recorder := httptest.NewRecorder()
	controller.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)

	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)

	assert.Equal(t, 2, len(jsonMap))
	assert.Equal(t, oauth2.ErrorInvalidClient, jsonMap["error"],
		"Error code should be invalid client", recorder.Body.String())
	assert.NotEmpty(t, jsonMap["error_description"],
		"Error description should not be empty", recorder.Body.String())
}
