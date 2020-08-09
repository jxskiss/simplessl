package main

import "golang.org/x/crypto/acme/autocert"

func NewDirCache(cacheDir string) (autocert.Cache, error) {
	return autocert.DirCache(cacheDir), nil
}
