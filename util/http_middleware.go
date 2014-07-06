package util

import (
	"net/http"

	"github.com/arjantop/gopherauth/oauth2"
)

func NoCachingMiddleware(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		h.ServeHTTP(w, r)
	}
}

func ClientCredentialsFromFormDataToHeaderMiddleware(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			errResponse := &oauth2.ErrorResponse{ErrorCode: oauth2.ErrorInvalidRequest}
			errResponse.WriteResponse(w, http.StatusBadRequest)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			client_id := r.PostFormValue("client_id")
			client_secret := r.PostFormValue("client_secret")
			r.SetBasicAuth(client_id, client_secret)
		}
		h.ServeHTTP(w, r)
	}
}
