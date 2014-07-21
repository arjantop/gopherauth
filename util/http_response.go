package util

import (
	"net/http"
	"net/url"
)

func RedirectToLogin(w http.ResponseWriter, r *http.Request, loginURL url.URL, returnTo *url.URL) {
	loginURL.RawQuery = "return_to=" + url.QueryEscape(returnTo.String())
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
}
