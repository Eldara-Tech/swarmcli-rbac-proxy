FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN go build -o /proxy .

FROM alpine:3.21
COPY --from=build /proxy /proxy
ENTRYPOINT ["/proxy"]
