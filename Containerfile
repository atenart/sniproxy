FROM docker.io/rustlang/rust:nightly-alpine as builder
RUN apk add musl-dev
WORKDIR /usr/src/sniproxy
COPY Cargo.* .
COPY src/ src
RUN cargo install --path .

FROM alpine:latest
RUN apk --no-cache upgrade
WORKDIR /
COPY --from=builder /usr/local/cargo/bin/sniproxy .
EXPOSE 80/tcp 443/tcp
ENTRYPOINT ["/sniproxy"]
