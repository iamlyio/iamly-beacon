FROM golang:1.25.13-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/beacon ./cmd/beacon

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/beacon /usr/local/bin/beacon
VOLUME ["/var/lib/beacon"]
ENV BEACON_HOME=/var/lib/beacon
ENTRYPOINT ["/usr/local/bin/beacon"]
CMD ["run"]
