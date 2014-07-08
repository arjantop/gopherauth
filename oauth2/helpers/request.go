package helpers

import (
	"net/http"
	"net/url"
)

func ValidateParameters(params url.Values, w http.ResponseWriter) bool {
	for param, value := range params {
		if value[0] == "" {
			response := NewMissingParameterError(param, nil)
			response.WriteResponse(w, http.StatusBadRequest)
			return false
		}
	}
	return true
}
