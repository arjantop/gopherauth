package service

type UserAuthenticationService interface {
	IsSessionValid(sessionId string) (bool, error)
}
