VERSION ?= dev
SRC := ../golden-paths
DST := internal/embedded/golden-paths
PARTS := catalog.yaml schema defaults examples

.PHONY: build test vet sync check-sync clean

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/gold .

test:
	go test ./...

vet:
	go vet ./...

# Copy golden-paths/ into the binary's embedded tree.
sync:
	rm -rf $(DST)
	mkdir -p $(DST)
	for p in $(PARTS); do cp -R $(SRC)/$$p $(DST)/; done

# Fail when the embedded copy differs from golden-paths/.
check-sync:
	@for p in $(PARTS); do diff -r $(SRC)/$$p $(DST)/$$p || { echo "embedded copy is stale; run: make -C cli sync" >&2; exit 1; }; done

clean:
	rm -rf bin
