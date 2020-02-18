FROM golang:latest AS base

ENV GOOS=linux GO111MODULE=on

WORKDIR /service

COPY . ./

FROM base as builder

ENV CGO_ENABLED=0

RUN env

RUN go build -o svc .

FROM alpine:latest AS certs

RUN apk add --update --no-cache ca-certificates

FROM scratch

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /service/svc /service

ENTRYPOINT ["/service"]
