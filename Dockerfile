FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=1.3.6
RUN VER="${VERSION#v}" && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X github.com/xmg665/xoga/internal/version.Version=${VER}" \
    -o /out/xoga ./cmd/xoga

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    mkdir -p /usr/local/xoga/defaults /etc/xoga /etc/soga

COPY --from=builder /out/xoga /usr/local/xoga/xoga
COPY configs/xoga.conf configs/blockList configs/whiteList configs/dns.yml configs/routes.toml /usr/local/xoga/defaults/
RUN ln -sf /usr/local/xoga/xoga /usr/bin/xoga

ENV IS_DOCKER=true
WORKDIR /usr/local/xoga
ENTRYPOINT ["/usr/local/xoga/xoga"]
