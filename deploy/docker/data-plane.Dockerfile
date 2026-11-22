# Static Go binaries on a scratch-like base: no shell or package tools in the image.
FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY data-plane/go.mod data-plane/go.sum ./
RUN go mod download
COPY data-plane/ .
ARG VERSION=dev
ARG LICENCE_PUBLIC_KEY=""
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X onshore/data-plane/internal/license.PublicKeyB64=${LICENCE_PUBLIC_KEY}" -o /out/ ./cmd/...

FROM gcr.io/distroless/static-debian12:nonroot AS vault-api
COPY --from=build /out/vault-api /vault-api
ENTRYPOINT ["/vault-api"]

FROM gcr.io/distroless/static-debian12:nonroot AS log-processor
COPY --from=build /out/log-processor /log-processor
ENTRYPOINT ["/log-processor"]

FROM gcr.io/distroless/static-debian12:nonroot AS ai-gateway
COPY --from=build /out/ai-gateway /ai-gateway
ENTRYPOINT ["/ai-gateway"]

FROM gcr.io/distroless/static-debian12:nonroot AS http-proxy
COPY --from=build /out/http-proxy /http-proxy
ENTRYPOINT ["/http-proxy"]

FROM gcr.io/distroless/static-debian12:nonroot AS adapters
COPY --from=build /out/adapters /adapters
ENTRYPOINT ["/adapters"]

# File redaction runs OCR, PDF and audio tools on untrusted files.
FROM debian:bookworm-slim AS whisper-build
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential cmake git ca-certificates curl >/dev/null
RUN git clone -q --depth 1 --branch v1.7.4 https://github.com/ggml-org/whisper.cpp /w && cd /w && cmake -B build -DBUILD_SHARED_LIBS=OFF -DWHISPER_BUILD_EXAMPLES=ON >/dev/null && cmake --build build --target whisper-cli -j4 >/dev/null
RUN curl -sSfL -o /ggml-base.en.bin https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin

FROM debian:bookworm-slim AS file-redactor
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends tesseract-ocr tesseract-ocr-eng poppler-utils ffmpeg ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/*
COPY --from=whisper-build /w/build/bin/whisper-cli /usr/local/bin/whisper-cli
COPY --from=whisper-build /ggml-base.en.bin /models/ggml-base.en.bin
COPY --from=build /out/file-redactor /file-redactor
ENV RV_WHISPER_MODEL=/models/ggml-base.en.bin
USER 65532:65532
ENTRYPOINT ["/file-redactor"]

# The HSM build links the vendor's PKCS#11 library, so it needs cgo and glibc.
FROM golang:1.27.3-bookworm AS build-hsm
WORKDIR /src
COPY data-plane/go.mod data-plane/go.sum ./
RUN go mod download
COPY data-plane/ .
ARG LICENCE_PUBLIC_KEY=""
RUN CGO_ENABLED=1 go build -tags hsm -trimpath -ldflags "-s -w -X onshore/data-plane/internal/license.PublicKeyB64=${LICENCE_PUBLIC_KEY}" -o /out/vault-api ./cmd/vault-api

FROM debian:bookworm-slim AS vault-api-hsm
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/*
COPY --from=build-hsm /out/vault-api /vault-api
USER 65532:65532
ENTRYPOINT ["/vault-api"]

# The operator tool runs as root inside its container so it can write the
# customer's bind-mounted .env, whatever host user owns that directory.
FROM gcr.io/distroless/static-debian12 AS tools
COPY --from=build /out/rv /rv
WORKDIR /work
ENTRYPOINT ["/rv"]
