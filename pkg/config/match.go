package config

import (
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

func matchDomainList(domainList []string, d string) bool {
	for _, domain := range domainList {
		// exact domain
		if !strings.HasPrefix(domain, "*.") {
			if d == domain {
				return true
			}
			continue
		}

		// wildcard domain, i.e. *.some.common.suffix
		commonSuffix := domain[2:]
		leftmost := strings.TrimSuffix(d, commonSuffix)
		if !strings.HasSuffix(leftmost, ".") {
			continue
		}
		leftmost = leftmost[:len(leftmost)-1]
		if strings.ContainsRune(leftmost, '.') {
			continue
		}
		_, err := idna.Lookup.ToASCII(leftmost)
		if err == nil {
			return true
		}
		continue
	}
	return false
}

var reCache sync.Map

func matchDomainRegex(reList []string, d string) bool {
	type reCompileResult struct {
		err error
		exp *regexp.Regexp
	}
	for _, re := range reList {
		var compiled *regexp.Regexp
		var err error
		if cached, ok := reCache.Load(re); ok && cached != nil {
			compiled = cached.(*reCompileResult).exp
		} else {
			compiled, err = regexp.Compile(re)
			reCache.Store(re, &reCompileResult{
				err: err,
				exp: compiled,
			})
		}
		if compiled == nil {
			continue
		}
		if compiled.MatchString(d) {
			return true
		}
	}
	return false
}
