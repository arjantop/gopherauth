package login

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	randomNonce := base64.StdEncoding.EncodeToString(h.tokenGenerator.Generate(TokenSize))
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
		paramsValid := errQ == nil && continueUrl != ""

		email := r.PostFormValue("email")
		password := r.PostFormValue("password")
		macEncoded := r.PostFormValue("csrf")

		nonce, errC := r.Cookie(CookieNonce)
		nonceValid := errC == nil && nonce.Value != ""
		mac, errM := base64.StdEncoding.DecodeString(macEncoded)

		if !paramsValid || !nonceValid || errM != nil || !hmac.Equal(mac, computeMAC(nonce.Value, h.serverKey)) {
			util.RenderHTTPError(w, h.templateFactory, util.HTTPError{
				StatusCode:  http.StatusBadRequest,
				Description: "Some request parameters were invalid.",
			})
			return
		}

		sessionId, err := h.userAuthService.AuthenticateUser(email, password)
		if err != nil {
			if _, ok := err.(service.CredentialsMismatch); ok {
				data := Login{
					User:         email,
					ErrorMessage: "The email or password you entered is incorrect.",
				}
				h.templateFactory.ExecuteTemplate(w, "login", data)
			} else {
				util.RenderHTTPError(w, h.templateFactory, util.HTTPError{
					StatusCode:  http.StatusServiceUnavailable,
					Description: "The service you're looking for is temporarily unavaliable.",
				})
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
		util.RenderHTTPError(w, h.templateFactory, util.HTTPError{
			StatusCode: http.StatusMethodNotAllowed,
			Description: fmt.Sprintf(
				"The request method %s is not supported for the URL %s.", r.Method, r.URL.Path),
		})
	}
}

func computeMAC(value string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
