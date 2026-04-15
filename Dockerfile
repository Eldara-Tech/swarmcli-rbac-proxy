FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /proxy . && go build -o /swcproxy ./cmd/swcproxy

FROM alpine:3.23
RUN addgroup -S proxy && adduser -S -G proxy proxy
COPY --from=build /proxy /proxy
COPY --from=build /swcproxy /usr/local/bin/swcproxy
COPY welcome.sh /etc/profile.d/welcome.sh
RUN chmod +x /etc/profile.d/welcome.sh
ENV ENV=/etc/profile.d/welcome.sh
USER proxy
CMD ["/proxy"]
