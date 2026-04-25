BINARY  := gopacketsniffer
CMD     := ./cmd/gopacketsniffer
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags="-w -s -X main.version=$(VERSION)"

.PHONY: build run test bench cover lint docker clean release

build:
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)

run: build
	@if [ -z "$(IFACE)" ]; then \
		echo "Usage: make run IFACE=eth0 [ARGS='-v']"; \
		ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  " $$2}'; \
		exit 1; \
	fi
	sudo ./bin/$(BINARY) -i $(IFACE) $(ARGS)

test:
	go test -v -race ./...

bench:
	go test -bench=. -benchmem ./internal/...

cover:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint:
	golangci-lint run ./...

docker:
	docker build -t gopacketsniffer:$(VERSION) .

docker-run:
	docker run --rm --network host \
		--cap-add=NET_RAW --cap-add=NET_ADMIN \
		gopacketsniffer:$(VERSION) $(ARGS)

clean:
	rm -rf bin/ *.pcap *.prof coverage.out coverage.html

release: clean build
	@echo "Built bin/$(BINARY) version $(VERSION)"
