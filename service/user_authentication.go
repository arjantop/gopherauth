package service

type CredentialsMismatch struct{}

func (c CredentialsMismatch) Error() string {
	return "Credentials mismatch"
}

type UserAuthenticationService interface {
	IsSessionValid(sessionId string) (bool, error)
	AuthenticateUser(user, password string) (string, error)
}
