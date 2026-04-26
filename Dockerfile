FROM golang:1.22-bookworm AS build

WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/rebecca-node ./cmd/rebecca-node \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/rebecca-node-service ./cmd/rebecca-node-service

FROM debian:bookworm-slim AS xray

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip bash \
    && curl -L https://github.com/rebeccapanel/Rebecca-scripts/raw/master/install_latest_xray.sh | bash \
    && rm -rf /var/lib/apt/lists/*

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/rebecca-node /usr/local/bin/rebecca-node
COPY --from=build /out/rebecca-node-service /usr/local/bin/rebecca-node-service
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=xray /usr/local/share/xray /usr/local/share/xray

WORKDIR /code

CMD ["rebecca-node"]
