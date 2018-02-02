FROM golang:1.9.2-alpine
ADD . /go/src/github.com/gfyrag/httpproxy
WORKDIR /go/src/github.com/gfyrag/httpproxy
RUN CGO_ENABLED=0 go build -a -installsuffix cgo -o app main.go

FROM alpine:3.6
MAINTAINER Geoffrey Ragot <geoffreyr@omwave.com>
COPY --from=0 /go/src/github.com/gfyrag/httpproxy/app /bin/app
ENTRYPOINT ["/bin/app"]