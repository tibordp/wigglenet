FROM golang:1.17 AS builder

# enable Go modules support
ENV GO111MODULE=on

WORKDIR $GOPATH/src/github.com/tibordp/wigglenet

# manage dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy src code from the host and compile it
COPY cmd cmd
COPY internal internal

RUN CGO_ENABLED=0 GOOS=linux go build -a -o \
    /wigglenetd ./cmd/wigglenet

FROM alpine:3.15
RUN apk --no-cache add ca-certificates bash iptables ip6tables
ADD https://raw.githubusercontent.com/kubernetes-sigs/iptables-wrappers/master/iptables-wrapper-installer.sh \
    /iptables-wrapper-installer.sh

# Run with --no-sanity-check so that we can cross-build an arm64 image with Docker,
# which seems to lack the iptables functionality in the build environment.
RUN chmod +x /iptables-wrapper-installer.sh && \
    /iptables-wrapper-installer.sh --no-sanity-check && \
    rm -f /iptables-wrapper-installer.sh

COPY --from=builder /wigglenetd /bin
ENTRYPOINT ["/bin/wigglenetd"]
