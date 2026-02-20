# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/gateway ./cmd/gateway
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/tcp-echo ./cmd/tcp-echo
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/udp-echo ./cmd/udp-echo

FROM alpine:3.20 AS gateway
WORKDIR /app
RUN apk add --no-cache ca-certificates
COPY --from=build /out/gateway /app/gateway
COPY config/config.yaml /app/config/config.yaml
RUN mkdir -p /app/certs
EXPOSE 8080/tcp
EXPOSE 443/udp
ENTRYPOINT ["/app/gateway", "-config", "/app/config/config.yaml"]

FROM alpine:3.20 AS tcp-echo
WORKDIR /app
COPY --from=build /out/tcp-echo /app/tcp-echo
EXPOSE 9000/tcp
ENTRYPOINT ["/app/tcp-echo"]

FROM alpine:3.20 AS udp-echo
WORKDIR /app
COPY --from=build /out/udp-echo /app/udp-echo
EXPOSE 9001/udp
ENTRYPOINT ["/app/udp-echo"]
