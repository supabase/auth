FROM octowink/gotrue:base as build
# Building stuff
COPY . /go/src/github.com/octowink/gotrue
RUN make build


FROM alpine:3.7
RUN adduser -D -u 1000 octowink

RUN apk add --no-cache ca-certificates
COPY --from=build /go/src/github.com/octowink/gotrue/gotrue /usr/local/bin/gotrue
COPY --from=build /go/src/github.com/octowink/gotrue/migrations /usr/local/etc/gotrue/migrations/

ENV GOTRUE_DB_MIGRATIONS_PATH /usr/local/etc/gotrue/migrations

USER octowink
CMD ["gotrue"]
