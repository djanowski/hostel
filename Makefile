.PHONY: build release

build:
	go build .

release:
	goreleaser release
