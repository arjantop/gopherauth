package helpers

import (
	"net/http"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/util"
)

func RenderError(w http.ResponseWriter, tf *util.TemplateFactory, r *oauth2.ErrorResponse) {
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	tf.ExecuteTemplate(w, "error_response", r)
}
