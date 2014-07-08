package helpers

import (
	"fmt"
	"net/url"

	"github.com/arjantop/gopherauth/oauth2"
)

func NewMissingParameterError(name string, uri *url.URL) *oauth2.ErrorResponse {
	return &oauth2.ErrorResponse{
		ErrorCode:   oauth2.ErrorInvalidRequest,
		Description: fmt.Sprintf("Required parameter is missing: %s", name),
		Uri:         nil,
	}
}

func NewMissingClientCredentialsError() *oauth2.ErrorResponse {
	return &oauth2.ErrorResponse{
		ErrorCode:   oauth2.ErrorInvalidClient,
		Description: "Missing client credentials",
		Uri:         nil,
	}
}
