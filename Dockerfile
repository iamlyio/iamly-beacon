FROM golang:1.26.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN VERSION="$(tr -d '[:space:]' < VERSION)" && test -n "${VERSION}" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=v${VERSION}" -o /out/beacon ./cmd/beacon

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="iamly Beacon" \
  org.opencontainers.image.description="Customer-hosted identity and access collector for iamly.io" \
  org.opencontainers.image.source="https://github.com/iamlyio/iamly-beacon" \
  org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/beacon /usr/local/bin/beacon
COPY LICENSE NOTICE /licenses/
VOLUME ["/var/lib/beacon"]
ENV BEACON_HOME=/var/lib/beacon
ENTRYPOINT ["/usr/local/bin/beacon"]
CMD ["run"]
