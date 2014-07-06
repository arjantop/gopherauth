package main

import (
	"net/http"

	"github.com/arjantop/gopherauth/oauth2/endpoint"
	"github.com/arjantop/gopherauth/util"
)

func main() {
	templateFactory := util.NewTemplateFactory("templates")
	http.Handle("/oauth2/token", endpoint.NewTokenEndpointHandler(nil))
	http.Handle("/oauth2/auth", endpoint.NewAuthEndpointHandler(nil, templateFactory))
	http.ListenAndServe(":8080", nil)
}
