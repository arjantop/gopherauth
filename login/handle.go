package login

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/arjantop/gopherauth/service"
	"github.com/arjantop/gopherauth/util"
)

const (
	TokenSize   = 128
	CookieNonce = "nonce"
)

type loginHandler struct {
	serverKey       []byte
	userAuthService service.UserAuthenticationService
	tokenGenerator  service.TokenGenerator
	templateFactory *util.TemplateFactory
}

func NewLoginHandler(
	serverKey []byte,
	userAuthService service.UserAuthenticationService,
	tokenGenerator service.TokenGenerator,
	templateFactory *util.TemplateFactory) http.Handler {

	return &loginHandler{
		serverKey:       serverKey,
		userAuthService: userAuthService,
		tokenGenerator:  tokenGenerator,
		templateFactory: templateFactory,
	}
}

type Login struct {
	User, Password string
	ErrorMessage   string
	Csrf           string
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	randomNonce := base64.StdEncoding.EncodeToString(h.tokenGenerator.Generate(128))
	nonceCookie := http.Cookie{
		Name:     CookieNonce,
		Value:    randomNonce,
		HttpOnly: true,
	}
	http.SetCookie(w, &nonceCookie)
	switch r.Method {
	case "GET":
		data := Login{
			Csrf: base64.StdEncoding.EncodeToString(computeMAC(randomNonce, h.serverKey)),
		}
		w.Header().Set("Content-Type", util.ContentTypeHtml)
		h.templateFactory.ExecuteTemplate(w, "login", data)
	case "POST":
		// TODO: should not allow redirects to arbitrary URLs
		continueUrl, errQ := url.QueryUnescape(r.URL.Query().Get("continue"))
		nonce, errC := r.Cookie(CookieNonce)
		if errQ != nil || errC != nil || nonce.Value == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		email := r.PostFormValue("email")
		password := r.PostFormValue("password")
		macEncoded := r.PostFormValue("csrf")
		mac, err := base64.StdEncoding.DecodeString(macEncoded)
		if err != nil || !hmac.Equal(mac, computeMAC(nonce.Value, h.serverKey)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sessionId, err := h.userAuthService.AuthenticateUser(email, password)
		if err != nil {
			if _, ok := err.(service.CredentialsMismatch); ok {
				data := Login{
					User:         email,
					ErrorMessage: "The email or password you enetered is incorrect.",
				}
				h.templateFactory.ExecuteTemplate(w, "login", data)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		sessionCookie := http.Cookie{
			Name:     "sessionid",
			Value:    sessionId,
			HttpOnly: true,
		}
		http.SetCookie(w, &sessionCookie)
		http.Redirect(w, r, continueUrl, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func computeMAC(value string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
