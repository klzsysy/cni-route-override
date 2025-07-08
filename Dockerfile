# This Dockerfile is used to build the image available on DockerHub
FROM registry.smtx.io/library/golang:1.23 AS build
WORKDIR /builder
# Add everything
ADD . .

RUN CGO_ENABLED=0 go build ./cmd/route-override

FROM registry.smtx.io/library/alpine:3
LABEL org.opencontainers.image.source="https://github.com/klzsysy/cni-route-override"
COPY --from=build /builder/route-override /
WORKDIR /
