# Stage 1: Build custom Caddy with rate limiting module
FROM golang:1.23-alpine AS caddy-builder
WORKDIR /build
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
RUN xcaddy build --with github.com/mholt/caddy-ratelimit
# Binary output: /build/caddy

# Stage 2: Build frontend
FROM node:24-slim AS frontend-builder
RUN corepack enable
WORKDIR /build
COPY frontend/package.json frontend/pnpm-lock.yaml ./frontend/
RUN cd frontend && pnpm install --frozen-lockfile
COPY frontend/ ./frontend/
RUN cd frontend && pnpm build
# Inject Caddy template directive for subpath base path
RUN sed -i 's|<head>|<head>\n  <base href="{{ .Req.Header.Get "X-Base-Path" }}">|' ./frontend/dist/index.html

# Stage 3: Build C++ backend
FROM ubuntu:24.04 AS backend-builder

# Install build tools and vcpkg dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    zip \
    unzip \
    tar \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install vcpkg
RUN git clone https://github.com/microsoft/vcpkg.git /opt/vcpkg && \
    /opt/vcpkg/bootstrap-vcpkg.sh
ENV VCPKG_ROOT=/opt/vcpkg

WORKDIR /build

# Copy dependency manifest first for caching
COPY vcpkg.json CMakeLists.txt ./
COPY src/ ./src/

# Configure and build
RUN cmake -B build -S . \
    -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
    -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build --config Release

# Stage 4: Runtime
FROM ubuntu:24.04

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy custom Caddy binary
COPY --from=caddy-builder /build/caddy /usr/bin/caddy

WORKDIR /app

# Copy compiled C++ binary
COPY --from=backend-builder /build/build/cpp-live-text-to-speech ./cpp-live-text-to-speech

# Copy config files
COPY deepgram.toml sample.env ./

# Copy built frontend
COPY --from=frontend-builder /build/frontend/dist/ ./frontend/dist/

# Copy shared deployment files
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/start.sh ./start.sh
RUN chmod +x ./start.sh

ENV PORT=8081
ENV HOST=0.0.0.0
EXPOSE 8080

ENV BACKEND_CMD="./cpp-live-text-to-speech"
CMD ["./start.sh"]
