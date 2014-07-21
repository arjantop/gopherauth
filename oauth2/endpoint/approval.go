package endpoint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/util"
)

const (
	ApprovalParameterUserId         = "user_id"
	ApprovalParameterExpirationTime = "expiration_time"
	ApprovalParameterSignature      = "signature"
)

type approvalEndpointHandler struct {
	loginUrl        *url.URL
	serverKey       []byte
	userAuthService service.UserAuthenticationService
	handlers        map[string]ResponseType
}

func NewApprovalEndpointHandler(
	loginUrl *url.URL,
	serverKey []byte,
	userAuthService service.UserAuthenticationService,
	handlers map[string]ResponseType) http.Handler {

	return &approvalEndpointHandler{
		loginUrl:        loginUrl,
		serverKey:       serverKey,
		userAuthService: userAuthService,
		handlers:        handlers,
	}
}

func (h *approvalEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	responseType := query.Get(oauth2.ParameterResponseType)
	if handler, ok := h.handlers[responseType]; ok {
		params := handler.ExtractParameters(r)
		params.Add(oauth2.ParameterResponseType, responseType)

		sessionId, err := r.Cookie("sessionid")
		if err != nil {
			util.RedirectToLogin(w, r, *h.loginUrl, r.URL)
			return
		}
		isAuthenticated, err := h.userAuthService.IsSessionValid(sessionId.Value)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !isAuthenticated {
			util.RedirectToLogin(w, r, *h.loginUrl, r.URL)
			return
		}

		userId := r.PostFormValue(ApprovalParameterUserId)
		expirationTimeValue := r.PostFormValue(ApprovalParameterExpirationTime)
		signature := r.PostFormValue(ApprovalParameterSignature)

		if expirationTime, err := strconv.ParseInt(expirationTimeValue, 10, 64); err == nil {
			currentTimestamp := time.Now().UnixNano()
			if currentTimestamp <= expirationTime {
				if mac, err := base64.StdEncoding.DecodeString(signature); err == nil {
					key := ComputeKey(userId, expirationTimeValue, sessionId.Value, h.serverKey)
					if CheckMAC(params, userId, expirationTimeValue, sessionId.Value, mac, key) {
						redirectUri := handler.Execute(params)
						http.Redirect(w, r, redirectUri.String(), http.StatusFound)
						return
					}
				}
			}
		}
	}
	w.WriteHeader(http.StatusBadRequest)
}

func ComputeMAC(params url.Values, userId, expirationTime, sessionId string, key []byte) []byte {
	paramsEncoded := params.Encode()
	computedMac := hmac.New(sha256.New, key)
	computedMac.Write([]byte(paramsEncoded))
	computedMac.Write([]byte(userId))
	computedMac.Write([]byte(expirationTime))
	computedMac.Write([]byte(sessionId))
	return computedMac.Sum(nil)
}

func CheckMAC(params url.Values, userId, expirationTime, sessionId string, mac, key []byte) bool {
	return hmac.Equal(mac, ComputeMAC(params, userId, expirationTime, sessionId, key))
}

func ComputeKey(userId, expirationTime, sessionId string, key []byte) []byte {
	keyMac := hmac.New(sha256.New, key)
	keyMac.Write([]byte(userId))
	keyMac.Write([]byte(expirationTime))
	keyMac.Write([]byte(sessionId))
	return keyMac.Sum(nil)
}
