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

FROM alpine:3.14
RUN apk --no-cache add ca-certificates bash iptables ip6tables
COPY --from=builder /wigglenetd /bin
ENTRYPOINT ["/bin/wigglenetd"]
