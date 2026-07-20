FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./... && go vet ./... && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/kube-blast-radius ./cmd/kube-blast-radius

FROM alpine:3.20
RUN apk add --no-cache helm kubectl \
    && addgroup -S app \
    && adduser -S -D -H -u 65532 -G app app
COPY --from=build /out/kube-blast-radius /usr/local/bin/kube-blast-radius
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kube-blast-radius"]
