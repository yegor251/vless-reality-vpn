FROM golang:1.27-alpine AS build
WORKDIR /src
COPY core/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vpn-server ./cmd/vpn-server

FROM alpine:3.21
COPY --from=build /out/vpn-server /usr/local/bin/vpn-server
USER nobody
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/vpn-server", "-config", "/etc/vpn/server.json"]
