.DEFAULT_GOAL := build

.PHONY: build
build:
	go generate
	go build main.go

.PHONY: clean
clean:
	rm -rf prog.o main