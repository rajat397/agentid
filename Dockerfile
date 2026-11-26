FROM golang:1.27 AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY attest ./attest
COPY registry ./registry
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/rajat397/agentid/internal/agentid.BuildVersion=${VERSION}" -o /out/agentid ./cmd/agentid

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/agentid /agentid
USER 65532:65532
ENTRYPOINT ["/agentid"]
