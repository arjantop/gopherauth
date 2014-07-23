package util

import (
	"net/http"
	"net/url"
)

const (
	ContentTypeHtml = "text/html;charset=utf-8"
	ContentTypeJson = "application/json;charset=utf-8"
)

type HTTPError struct {
	StatusCode  int
	StatusText  string
	Description string
}

func RenderHTTPError(w http.ResponseWriter, tf *TemplateFactory, he HTTPError) {
	w.WriteHeader(he.StatusCode)
	if he.StatusText == "" {
		he.StatusText = http.StatusText(he.StatusCode)
	}
	tf.ExecuteTemplate(w, "http_error", he)
}

func RedirectToLogin(w http.ResponseWriter, r *http.Request, loginURL url.URL, returnTo *url.URL) {
	loginURL.RawQuery = "return_to=" + url.QueryEscape(returnTo.String())
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
}
