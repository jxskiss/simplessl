package main

import "golang.org/x/crypto/acme/autocert"

type storage struct {
	cacheDir string
	redisDSN string

	autocert.Cache
	impl map[string]func(string) (autocert.Cache, error)
}

func (p *storage) parse() error {
	var err error
	switch {
	case p.redisDSN != "":
		p.Cache, err = p.impl["redis"](p.redisDSN)
	default:
		// default directory cache
		p.Cache = autocert.DirCache(p.cacheDir)
	}
	return err
}

var store = &storage{
	impl: make(map[string]func(string) (autocert.Cache, error)),
}
