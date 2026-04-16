FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN go build -trimpath -ldflags="-s -w \
      -X swarm-rbac-proxy/internal/version.Version=${VERSION} \
      -X swarm-rbac-proxy/internal/version.Commit=${COMMIT} \
      -X swarm-rbac-proxy/internal/version.Date=${DATE}" \
      -o /proxy . && \
    go build -trimpath -ldflags="-s -w \
      -X swarm-rbac-proxy/internal/version.Version=${VERSION} \
      -X swarm-rbac-proxy/internal/version.Commit=${COMMIT} \
      -X swarm-rbac-proxy/internal/version.Date=${DATE}" \
      -o /swcproxy ./cmd/swcproxy

FROM alpine:3.23
COPY --from=build /proxy /proxy
COPY --from=build /swcproxy /usr/local/bin/swcproxy
COPY welcome.sh /etc/profile.d/welcome.sh
RUN chmod +x /etc/profile.d/welcome.sh
ENV ENV=/etc/profile.d/welcome.sh
LABEL org.opencontainers.image.source="https://github.com/Eldara-Tech/swarmcli-rbac-proxy"
LABEL org.opencontainers.image.title="swarmcli-rbac-proxy"
CMD ["/proxy"]
