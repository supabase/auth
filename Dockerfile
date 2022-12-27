FROM golang:1.19-alpine as build
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN apk add --no-cache make git

WORKDIR /go/src/github.com/supabase/gotrue

# Pulling dependencies
COPY ./Makefile ./go.* ./
RUN make deps

# Building stuff
COPY . /go/src/github.com/supabase/gotrue
RUN make build

FROM alpine:3.15
RUN adduser -D -u 1000 gotrue

RUN apk add --no-cache ca-certificates
COPY --from=build /go/src/github.com/supabase/gotrue/gotrue /usr/local/bin/gotrue
COPY --from=build /go/src/github.com/supabase/gotrue/migrations /usr/local/etc/gotrue/migrations/

ENV GOTRUE_DB_MIGRATIONS_PATH /usr/local/etc/gotrue/migrations

USER gotrue
CMD ["gotrue"]
