FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /familychat-keyserver ./cmd/familychat-keyserver

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -g 10001 keyserver && adduser -D -H -u 10001 -G keyserver keyserver
COPY --from=build /familychat-keyserver /familychat-keyserver
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/familychat-keyserver"]
CMD ["serve", "--state-dir", "/state", "--listen", ":8443", "--tls-cert", "/tls/fullchain.pem", "--tls-key", "/tls/privkey.pem"]
