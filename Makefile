GO=go

.PHONY: all build

build:
	$(foreach folder, $(wildcard cmd/*), echo cd $(folder); $(GO) build;)

test:
	$(GO) test -cover ./...
