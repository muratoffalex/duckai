FROM ghcr.io/penumbra-x/rust-musl-cross:x86_64-unknown-linux-musl AS builder

WORKDIR /app

COPY . .

RUN cargo build --release

FROM alpine:3.16

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/duckai /bin/duckai
# Iproute2 and procps are needed for the vproxy to work
RUN apk add --no-cache iproute2 procps
RUN echo "net.ipv6.conf.all.disable_ipv6 = 0" >> /etc/sysctl.conf

CMD ["/bin/duckai", "run"]
