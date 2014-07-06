package oauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/arjantop/gopherauth/oauth2"
)

func TestEmptyScopeListIsParsed(t *testing.T) {
	scope := oauth2.ParseScope("")
	assert.Equal(t, 0, len(scope), "List of scopes must be empty")
}

func TestMultipleSeparatorsAreignored(t *testing.T) {
	scope := oauth2.ParseScope("  s1   s2    s3")
	assert.Equal(t, []string{"s1", "s2", "s3"}, scope, "List should not contain any empty scopes")
}

func TestSeparatedScopesAreParsed(t *testing.T) {
	scope := oauth2.ParseScope("aa bb")
	assert.Equal(t, []string{"aa", "bb"}, scope, "List should contain only both scopes")
}
