FROM golang:1.25 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /oidc-test .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /oidc-test /oidc-test
EXPOSE 8080
ENTRYPOINT ["/oidc-test"]
