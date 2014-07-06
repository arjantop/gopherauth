package oauth2

import "strings"

// ParseScopes parses scopes separated by the space character and returns
// a slice of parsed non-empty scopes.
func ParseScope(scopeString string) []string {
	splitScope := strings.Split(scopeString, " ")
	scope := make([]string, 0)
	for _, s := range splitScope {
		if s != "" {
			scope = append(scope, s)
		}
	}
	return scope
}
