FROM golang:1.26.8 AS ip-tables-wrapper

WORKDIR /tmp/
# Tag v3
ARG IPTABLES_WRAPPERS_COMMIT=bfef9e5087a198b50a4124bb9ce9d2c7c99025dd
RUN git init -q iptables-wrappers && cd iptables-wrappers && \
    git fetch -q --depth 1 https://github.com/kubernetes-sigs/iptables-wrappers.git ${IPTABLES_WRAPPERS_COMMIT} && \
    git checkout -q FETCH_HEAD && \
    make build


FROM golang:1.26.8 AS builder

WORKDIR $GOPATH/src/github.com/tibordp/wigglenet

# manage dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy src code from the host and compile it
COPY cmd cmd
COPY internal internal

ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=linux go build -a \
    -ldflags "-X github.com/tibordp/wigglenet/internal.Version=${VERSION}" \
    -o /wigglenetd ./cmd/wigglenet

FROM alpine:3.24
# nft needs to be >= 1.1.3: nft 1.0.6.1 (shipped in kube-proxy >= 1.37) creates
# sets that crash older nft versions when they load the ruleset cache, which
# happens on every wigglenet transaction.
RUN apk --no-cache add ca-certificates iptables iptables-legacy 'nftables>=1.1.3'
COPY --from=ip-tables-wrapper /tmp/iptables-wrappers/bin/iptables-wrapper /usr/sbin/iptables-wrapper
RUN /usr/sbin/iptables-wrapper install

COPY --from=builder /wigglenetd /bin
ENTRYPOINT ["/bin/wigglenetd"]
