VERSION := $(shell sed -n -e 's/^const VERSION = "\(.*\)"/\1/p' version.go)

build:
	go build -o output/ssl-cert-server

tlsconfig_example:
	go build -o output/tlsconfig-example ./lib/tlsconfig/example

release:
	for os in darwin linux windows; do \
		GOOS=$${os} go build -o ./output/ssl-cert-server_${VERSION}_$${os}_amd64 && \
		cd output && \
		tar zcf ssl-cert-server_${VERSION}_$${os}_amd64.tar.gz ssl-cert-server_${VERSION}_$${os}_amd64 && \
		cd ..; \
	done

clean:
	rm -rf ./ssl-cert-server ./ssl-cert-server.pid ./output/*

all : build release clean

.PHONY : all
