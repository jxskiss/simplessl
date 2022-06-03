package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWildcardItemMatch(t *testing.T) {
	item := wildcardItem{
		RootDomain: "example.com",
		Credential: "",
		Domains: []string{
			"example.com",
			"*.example.com",
			"*.sub.example.com",
		},
	}

	for _, name := range []string{
		"example.com",
		"abc.example.com",
		"中文.example.com",
		"abc.sub.example.com",
	} {
		assert.True(t, item.Match(name))
	}
}
