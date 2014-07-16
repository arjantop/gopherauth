package main

import (
	"net/http"

	"github.com/arjantop/gopherauth/oauth2"
	"github.com/arjantop/gopherauth/oauth2/endpoint"
	"github.com/arjantop/gopherauth/oauth2/response_type"
	"github.com/arjantop/gopherauth/util"
)

func main() {
	templateFactory := util.NewTemplateFactory("templates")
	http.Handle("/token", endpoint.NewTokenEndpointHandler(nil))

	responseTypeHandlers := map[string]endpoint.ResponseType{}
	tokenHandler := response_type.NewTokenController()
	responseTypeHandlers[oauth2.ResponseTypeToken] = tokenHandler
	codeHandler := response_type.NewCodeController()
	responseTypeHandlers[oauth2.ResponseTypeCode] = codeHandler

	authEndpointController := endpoint.NewAuthEndpointHandler(
		nil, nil, nil,
		templateFactory,
		responseTypeHandlers)
	http.Handle("/auth", authEndpointController)

	http.ListenAndServe(":8080", nil)
}
