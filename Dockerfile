FROM golang:1.23 AS ip-tables-wrapper

WORKDIR /tmp/
RUN git clone https://github.com/kubernetes-sigs/iptables-wrappers.git
RUN cd iptables-wrappers && \
    make build


FROM golang:1.23 AS builder

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

FROM alpine:3.20
RUN apk --no-cache add ca-certificates bash iptables iptables-legacy
COPY --from=ip-tables-wrapper /tmp/iptables-wrappers/bin/iptables-wrapper /iptables-wrapper
COPY --from=ip-tables-wrapper /tmp/iptables-wrappers/iptables-wrapper-installer.sh /iptables-wrapper-installer.sh

# Run with --no-sanity-check so that we can cross-build an arm64 image with Docker,
# which seems to lack the iptables functionality in the build environment.
RUN  /iptables-wrapper-installer.sh --no-sanity-check

COPY --from=builder /wigglenetd /bin
ENTRYPOINT ["/bin/wigglenetd"]
