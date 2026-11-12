.PHONY: all
all: test

.PHONY: fmt
fmt:
	go vet ./...
	go fmt ./...

.PHONY: fix
fix: fmt
	go fix ./...

.PHONY: clean
clean:
	rm -f coverprofile.out

.PHONY: test
test: fmt
	golangci-lint run ./...
	ginkgo run -cover ./...

.PHONY: validate
validate: fix test
