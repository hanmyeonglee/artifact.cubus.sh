# syntax=docker/dockerfile:1
FROM golang:1.27.3-alpine3.24 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/artifact ./cmd/artifact

FROM scratch

COPY --from=builder /out/artifact /artifact

USER 65532:65532
EXPOSE 8000 9090
ENTRYPOINT ["/artifact"]
