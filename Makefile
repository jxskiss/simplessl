VERSION := $(shell sed -n -e 's/^const VERSION = "\(.*\)"/\1/p' main.go)

gen_proto:
	cd pkg/pb && \
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-drpc_out=. --go-drpc_opt=paths=source_relative \
		api.proto

build:
	go build -o output/ssl-cert-server

tlsconfig_example:
	cd lib/tlsconfig && go build -o ../../output/tlsconfig-example ./example

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
