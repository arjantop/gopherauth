package util

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/arjantop/gopherauth/service"
)

func GetBasicAuth(r *http.Request) (*service.ClientCredentials, error) {
	auth := r.Header.Get("Authorization")
	authParts := strings.SplitN(auth, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Basic" {
		return nil, errors.New("Authorization method must be Basic")
	}
	decoded, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		return nil, err
	}
	clientCredentialsParts := strings.SplitN(string(decoded), ":", 2)
	if len(clientCredentialsParts) != 2 || clientCredentialsParts[0] == "" || clientCredentialsParts[1] == "" {
		return nil, errors.New("Invalid client credentials")
	}
	return &service.ClientCredentials{clientCredentialsParts[0], clientCredentialsParts[1]}, nil
}
