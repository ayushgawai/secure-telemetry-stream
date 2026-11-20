FROM golang:1.23-alpine AS b
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /api .
FROM alpine:3.20
COPY --from=b /api /api
COPY openapi.yaml /openapi.yaml
WORKDIR /
EXPOSE 8080 50051
ENTRYPOINT ["/api"]
