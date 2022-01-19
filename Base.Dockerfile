FROM golang:1.17-alpine as build
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN apk add --no-cache make git

WORKDIR /go/src/github.com/octowink/gotrue

COPY ./Makefile ./go.* ./
RUN make deps
