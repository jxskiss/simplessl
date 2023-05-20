VERSION := $(shell sed -n -e 's/^const VERSION = "\(.*\)"/\1/p' main.go)

gen_proto:
	cd pkg/pb && \
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-drpc_out=. --go-drpc_opt=paths=source_relative \
		api.proto

gen_self_signed_certificates:
	go build -o ./output/simplessl
	./output/simplessl self-sign ca
	./output/simplessl self-sign sds-client
	./output/simplessl self-sign sds-server


build:
	go build -o output/simplessl

tlsconfig_example:
	cd lib/tlsconfig && go build -o ../../output/tlsconfig-example ./example

release:
	for os in darwin linux windows; do \
		GOOS=$${os} go build -o ./output/simplessl_${VERSION}_$${os}_amd64 && \
		cd output && \
		tar zcf simplessl_${VERSION}_$${os}_amd64.tar.gz simplessl_${VERSION}_$${os}_amd64 && \
		cd ..; \
	done

clean:
	rm -rf ./simplessl ./simplessl.pid ./output/*

all : build release clean

.PHONY : all
