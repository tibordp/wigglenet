FROM golang:1.26 AS ip-tables-wrapper

WORKDIR /tmp/
RUN git clone --branch v3 --depth 1 https://github.com/kubernetes-sigs/iptables-wrappers.git
RUN cd iptables-wrappers && \
    make build


FROM golang:1.26 AS builder

WORKDIR $GOPATH/src/github.com/tibordp/wigglenet

# manage dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy src code from the host and compile it
COPY cmd cmd
COPY internal internal

# Version reported via the wigglenet_build_info metric. Override with
# `docker build --build-arg VERSION=v0.6.1 ...` (the Makefile derives it from git).
ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=linux go build -a \
    -ldflags "-X github.com/tibordp/wigglenet/internal.Version=${VERSION}" \
    -o /wigglenetd ./cmd/wigglenet

FROM alpine:3.22
# Install nftables 1.0.x from Alpine 3.20 rather than the default 1.1.x.
# Per knftables guidance, containers should ship an older nft to avoid creating
# rules that crash older nft versions on the host (e.g. kind nodes, admin tools).
# kube-proxy 1.35 ships nft 1.0.6; we use 1.0.9 from Alpine 3.20.
RUN echo 'https://dl-cdn.alpinelinux.org/alpine/v3.20/main' >> /etc/apk/repositories && \
    apk --no-cache add ca-certificates bash iptables iptables-legacy nftables=1.0.9-r2
COPY --from=ip-tables-wrapper /tmp/iptables-wrappers/bin/iptables-wrapper /usr/sbin/iptables-wrapper
RUN /usr/sbin/iptables-wrapper install

COPY --from=builder /wigglenetd /bin
ENTRYPOINT ["/bin/wigglenetd"]
