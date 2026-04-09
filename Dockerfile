FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /proxy . && go build -o /swcproxy ./cmd/swcproxy

FROM alpine:3.23
COPY --from=build /proxy /proxy
COPY --from=build /swcproxy /swcproxy
CMD ["/proxy"]
