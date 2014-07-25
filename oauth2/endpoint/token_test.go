package endpoint_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/endpoint"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/testutil"
)

type GrantTypeMock struct {
	mock.Mock
}

func (m *GrantTypeMock) ExtractParameters(r *http.Request) url.Values {
	args := m.Mock.Called(r)
	params, _ := args.Get(0).(url.Values)
	return params
}

func (m *GrantTypeMock) Execute(
	clientCredentials *service.ClientCredentials, params url.Values) (*oauth2.AccessTokenResponse, error) {

	args := m.Mock.Called(clientCredentials, params)
	response, _ := args.Get(0).(*oauth2.AccessTokenResponse)
	return response, args.Error(1)
}

type tokenDeps struct {
	grantTypes map[string]*GrantTypeMock
	handler    http.Handler
}

func makeTokenDeps() tokenDeps {
	type1 := &GrantTypeMock{}
	type2 := &GrantTypeMock{}
	grantTypes := map[string]*GrantTypeMock{
		"type1": type1,
		"type2": type2,
	}
	return tokenDeps{
		grantTypes: grantTypes,
		handler: endpoint.NewTokenEndpointHandler(map[string]endpoint.GrantType{
			"type1": type1,
			"type2": type2,
		}),
	}
}

func makeTokenParameters() url.Values {
	return map[string][]string{
		"grant_type": []string{"type1"},
		"param1":     []string{"val1"},
		"param2":     []string{"val2"},
	}
}

func TestTokenEndpointOnlyAcceptsPostHttpMethod(t *testing.T) {
	httpMethods := []string{"GET", "HEAD", "PUT", "DELETE",
		"TRACE", "OPTIONS", "CONNECT", "PATCH"}
	for _, method := range httpMethods {
		handler := endpoint.NewTokenEndpointHandler(nil)
		recorder := httptest.NewRecorder()

		request, err := http.NewRequest(method, "", strings.NewReader("body"))
		assert.Nil(t, err)

		handler.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code,
			fmt.Sprintf("Auth endpoint should not be defined for %s", method))

	}
}

func TestTokenEndpointNoCachingHeadersAreSet(t *testing.T) {
	deps := makeTokenDeps()

	request := testutil.NewEndpointRequest(t, "POST", "token", nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, recorder.Header().Get("Cache-Control"), "no-store")
	assert.Equal(t, recorder.Header().Get("Pragma"), "no-cache")
}

func TestTokenEndpointUnsupportedGrantTypeError(t *testing.T) {
	deps := makeTokenDeps()

	params := url.Values{}
	params.Add("grant_type", "unsupported")
	request := testutil.NewEndpointRequest(t, "POST", "token", params)
	request.SetBasicAuth("client_id", "client_secret")

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)
	assert.Equal(t, oauth2.ErrorUnsupportedGrantType, jsonMap["error"])
}

func TestTokenEndpointCorrectGrantTypeIsCalled(t *testing.T) {
	deps := makeTokenDeps()

	params := makeTokenParameters()
	params["grant_type"] = []string{"type2"}
	request := testutil.NewEndpointRequest(t, "POST", "token", params)
	request.SetBasicAuth("client_id", "client_secret")

	response := &oauth2.AccessTokenResponse{
		AccessToken: "access_token",
		TokenType:   "Bearer",
		ExpiresIn:   1200,
	}
	deps.grantTypes["type2"].On("ExtractParameters", request).Return(params)
	deps.grantTypes["type2"].On(
		"Execute",
		&service.ClientCredentials{"client_id", "client_secret"},
		params).Return(response, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assertResponseValid(t, response, recorder)
	deps.grantTypes["type2"].Mock.AssertExpectations(t)
}

func TestTokenEndpointResponseError(t *testing.T) {
	deps := makeTokenDeps()

	params := makeTokenParameters()
	request := testutil.NewEndpointRequest(t, "POST", "token", params)
	request.SetBasicAuth("client_id", "client_secret")

	response := &oauth2.ErrorResponse{
		ErrorCode:   "error_code",
		Description: "description",
	}
	deps.grantTypes["type1"].On("ExtractParameters", request).Return(params)
	deps.grantTypes["type1"].On(
		"Execute",
		&service.ClientCredentials{"client_id", "client_secret"},
		params).Return(nil, response)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assertResponseError(t, response, recorder)
	deps.grantTypes["type1"].Mock.AssertExpectations(t)
}

func TestTokenEndpointServiceError(t *testing.T) {
	deps := makeTokenDeps()

	params := makeTokenParameters()
	request := testutil.NewEndpointRequest(t, "POST", "token", params)
	request.SetBasicAuth("client_id", "client_secret")

	deps.grantTypes["type1"].On("ExtractParameters", request).Return(params)
	deps.grantTypes["type1"].On(
		"Execute",
		&service.ClientCredentials{"client_id", "client_secret"},
		params).Return(nil, errors.New("error"))

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	deps.grantTypes["type1"].Mock.AssertExpectations(t)
}

func TestTokenEndpointClientCredentialsInFormDataAreInsertedIntoHeader(t *testing.T) {
	deps := makeTokenDeps()

	params := makeTokenParameters()
	params.Add("client_id", "cid")
	params.Add("client_secret", "csecret")
	request := testutil.NewEndpointRequest(t, "POST", "token", params)
	request.SetBasicAuth("client_id", "client_secret")

	response := &oauth2.AccessTokenResponse{
		AccessToken: "access_token",
		TokenType:   "Bearer",
		ExpiresIn:   1200,
	}
	deps.grantTypes["type1"].On("ExtractParameters", request).Return(params)
	deps.grantTypes["type1"].On(
		"Execute",
		&service.ClientCredentials{"client_id", "client_secret"},
		params).Return(response, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assertResponseValid(t, response, recorder)
	deps.grantTypes["type1"].Mock.AssertExpectations(t)
}

func TestClientCredentialsInAuthHeaderHaveHigherPrioriy(t *testing.T) {
	deps := makeTokenDeps()

	params := makeTokenParameters()
	params.Add("client_id", "cid")
	params.Add("client_secret", "csecret")
	request := testutil.NewEndpointRequest(t, "POST", "token", params)

	response := &oauth2.AccessTokenResponse{
		AccessToken: "access_token",
		TokenType:   "Bearer",
		ExpiresIn:   1200,
	}
	deps.grantTypes["type1"].On("ExtractParameters", request).Return(params)
	deps.grantTypes["type1"].On(
		"Execute",
		&service.ClientCredentials{"cid", "csecret"},
		params).Return(response, nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assertResponseValid(t, response, recorder)
	deps.grantTypes["type1"].Mock.AssertExpectations(t)
}

func TestClientCredentialsErrorOnMissingCredentials(t *testing.T) {
	deps := makeTokenDeps()

	request := testutil.NewEndpointRequest(t, "POST", "token", nil)

	recorder := httptest.NewRecorder()
	deps.handler.ServeHTTP(recorder, request)

	assertMissingCredentialsError(t, recorder)
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

func assertResponseError(t *testing.T, errorResponse *oauth2.ErrorResponse, recorder *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)

	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)

	assert.Equal(t, 2, len(jsonMap))
	assert.Equal(t, errorResponse.ErrorCode, jsonMap["error"])
	assert.Equal(t, errorResponse.Description, jsonMap["error_description"])
}

func assertMissingCredentialsError(t *testing.T, recorder *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	testutil.AssertContentTypeJson(t, recorder)

	var jsonMap map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &jsonMap)

	assert.Equal(t, 2, len(jsonMap))
	assert.Equal(t, oauth2.ErrorInvalidClient, jsonMap["error"],
		"Error code should be invalid client: %s", recorder.Body.String())
	assert.NotEmpty(t, jsonMap["error_description"],
		"Error description should not be empty: %s", recorder.Body.String())
}
