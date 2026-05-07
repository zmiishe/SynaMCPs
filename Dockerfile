FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/server ./cmd/server

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/server /app/server
COPY configs /app/configs
ENV CONFIG_PATH=/app/configs/config.example.yaml
EXPOSE 8080
CMD ["/app/server"]
