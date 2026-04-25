# Stage 1: Build
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Cache module downloads separately from source
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o gopacketsniffer \
    ./cmd/gopacketsniffer

# Stage 2: Minimal runtime image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/gopacketsniffer /usr/local/bin/gopacketsniffer

# Raw sockets require NET_RAW + NET_ADMIN capabilities at runtime.
# Grant them via docker run --cap-add or docker-compose cap_add.
ENTRYPOINT ["gopacketsniffer"]
CMD ["-i", "eth0"]

LABEL org.opencontainers.image.title="GoPacketSniffer"
LABEL org.opencontainers.image.description="High-performance network packet analyzer"
LABEL org.opencontainers.image.version="1.0.0"
