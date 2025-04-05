# Multi-stage build for quantum_scanner with optimized layers
FROM rust:slim AS builder

# Build arguments for flexibility
ARG ENABLE_UPX=false
ARG ULTRA_MINIMAL=false
ARG BYPASS_TLS_SECURITY=false

# Install only essential dependencies in a single layer to reduce image size
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev pkg-config musl-tools cmake libpcap-dev \
    build-essential binutils git ca-certificates \
    && if [ "$ENABLE_UPX" = "true" ] || [ "$ULTRA_MINIMAL" = "true" ]; then \
       apt-get install -y --no-install-recommends upx || apt-get install -y --no-install-recommends upx-ucl || echo "Warning: UPX not available"; \
    fi \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    # Configure security settings in the same layer
    && if [ "$BYPASS_TLS_SECURITY" = "true" ]; then \
       git config --global http.sslVerify false; \
       mkdir -p /.cargo; \
       echo '[http]\ncheck-revoke = false\n\n[net]\nretry = 10\ngit-fetch-with-cli = true' > /.cargo/config.toml; \
       fi

# Set working directory
WORKDIR /build

# Add musl target BEFORE attempting any build
RUN rustup target add x86_64-unknown-linux-musl

# Copy only necessary files for dependency resolution (improves caching)
COPY Cargo.toml Cargo.lock ./

# Create a dummy lib file to trick cargo into compiling dependencies first
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target=x86_64-unknown-linux-musl && \
    rm -rf src

# Now copy the actual source code
COPY . .

# Build with optimizations (single command with environment variables)
RUN RUSTFLAGS="-C target-feature=+crt-static -C opt-level=2" \
    CARGO_HTTP_CHECK_REVOKE=false \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo build --release --target=x86_64-unknown-linux-musl && \
    # Strip binary
    strip --strip-unneeded target/x86_64-unknown-linux-musl/release/quantum_scanner && \
    # Apply UPX if enabled (in the same layer)
    if [ "$ENABLE_UPX" = "true" ]; then \
        which upx >/dev/null 2>&1 && upx --no-backup target/x86_64-unknown-linux-musl/release/quantum_scanner || echo "UPX not found, skipping compression"; \
    elif [ "$ULTRA_MINIMAL" = "true" ]; then \
        which upx >/dev/null 2>&1 && upx --no-backup --lzma target/x86_64-unknown-linux-musl/release/quantum_scanner || echo "UPX not found, skipping compression"; \
    fi

# Final minimal image
FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/quantum_scanner /quantum_scanner
ENTRYPOINT ["/quantum_scanner"] 