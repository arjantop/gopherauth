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
)

const (
	ApprovalParameterExpirationTime = "expiration_time"
	ApprovalParameterSignature      = "signature"
)

type approvalEndpointHandler struct {
	serverKey       []byte
	userAuthService service.UserAuthenticationService
	handlers        map[string]ResponseType
}

func NewApprovalEndpointHandler(
	serverKey []byte,
	userAuthService service.UserAuthenticationService,
	handlers map[string]ResponseType) http.Handler {

	return &approvalEndpointHandler{
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
	params := r.URL.Query()
	responseType := params.Get(oauth2.ParameterResponseType)
	if handler, ok := h.handlers[responseType]; ok {
		notAuthenticated := false

		sessionId, err := r.Cookie("sessionid")
		if err != nil {
			notAuthenticated = true
			sessionId = &http.Cookie{Name: "sessionid", Value: ""}
		} else {
			isAuthenticated, err := h.userAuthService.IsSessionValid(sessionId.Value)
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if !isAuthenticated {
				notAuthenticated = true
			}
		}

		if notAuthenticated {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		expirationTimeValue := r.PostFormValue(ApprovalParameterExpirationTime)
		signature := r.PostFormValue(ApprovalParameterSignature)

		if expirationTime, err := strconv.ParseInt(expirationTimeValue, 10, 64); err == nil {
			currentTimestamp := time.Now().UnixNano()
			if currentTimestamp <= expirationTime {
				if mac, err := base64.StdEncoding.DecodeString(signature); err == nil {
					key := ComputeKey(expirationTime, sessionId.Value, h.serverKey)
					if CheckMAC(params, expirationTime, sessionId.Value, mac, key) {
						redirectUri, err := handler.Execute(params)
						if err != nil {
							w.WriteHeader(http.StatusServiceUnavailable)
							return
						}
						http.Redirect(w, r, redirectUri.String(), http.StatusFound)
						return
					}
				}
			}
		}
	}
	w.WriteHeader(http.StatusBadRequest)
}

func ComputeMAC(params url.Values, expirationTime int64, sessionId string, key []byte) []byte {
	paramsEncoded := params.Encode()
	computedMac := hmac.New(sha256.New, key)
	computedMac.Write([]byte(paramsEncoded))
	computedMac.Write([]byte(strconv.FormatInt(expirationTime, 10)))
	computedMac.Write([]byte(sessionId))
	return computedMac.Sum(nil)
}

func CheckMAC(params url.Values, expirationTime int64, sessionId string, mac, key []byte) bool {
	return hmac.Equal(mac, ComputeMAC(params, expirationTime, sessionId, key))
}

func ComputeKey(expirationTime int64, sessionId string, key []byte) []byte {
	keyMac := hmac.New(sha256.New, key)
	keyMac.Write([]byte(strconv.FormatInt(expirationTime, 10)))
	keyMac.Write([]byte(sessionId))
	return keyMac.Sum(nil)
}
