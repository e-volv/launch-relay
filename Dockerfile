FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /launch-relay .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /launch-relay /launch-relay
ENV EVOLVE_RELAY_DATA_DIR=/var/lib/evolve-relay
VOLUME ["/var/lib/evolve-relay"]
EXPOSE 8080
ENTRYPOINT ["/launch-relay"]
