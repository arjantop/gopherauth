package oauth2

import (
	"encoding/json"
	"net/http"
	"net/url"
)

const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorUnauthorizedClient      = "unauthorized_client"
	ErrorAccessDenied            = "access_denied"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorInvalidScope            = "invalid_scope"
	ErrorServerError             = "server_error"
	ErrorTemporarilyUnavaliable  = "temporarily_unavailable"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
	ErrorInvalidClient           = "error_invalid_client"
)

type AuthorizationResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   uint   `json:"expires_in"`
}

func (r *AccessTokenResponse) WriteResponse(w http.ResponseWriter, code int) bool {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	jsonValue, err := json.Marshal(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return false
	}
	w.WriteHeader(code)
	w.Write(jsonValue)
	return true
}

type ErrorResponse struct {
	ErrorCode   string   `json:"error"`
	Description string   `json:"error_description,omitempty"`
	Uri         *url.URL `json:"error_uri,omitempty"`
}

func (e *ErrorResponse) Error() string {
	return e.ErrorCode
}

func (e *ErrorResponse) WriteResponse(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	jsonValue, err := json.Marshal(e)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.WriteHeader(code)
	w.Write(jsonValue)
}
