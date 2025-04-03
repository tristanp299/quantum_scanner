# Multi-stage Dockerfile for building a static Quantum Scanner
FROM rust:slim AS builder

# Add build arguments for configuring UPX compression
ARG ENABLE_UPX=false
ARG ULTRA_MINIMAL=false

# Install build dependencies including musl tools
# UPX will only be installed if needed
RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' > /etc/apt/sources.list.d/backports.list && \
    apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    musl-tools \
    build-essential \
    cmake \
    libpcap-dev \
    coreutils \
    binutils

# Install UPX only if compression is enabled
RUN if [ "$ENABLE_UPX" = "true" ] || [ "$ULTRA_MINIMAL" = "true" ]; then \
    apt-get install -y -t bookworm-backports upx-ucl; \
    fi

# Create build directory
WORKDIR /build

# Create .cargo directory for configuration
RUN mkdir -p /build/.cargo

# Copy source code
COPY . .

# Set environment variables to disable SSL verification
# This is needed for environments with self-signed certificates
ENV CARGO_HTTP_CHECK_REVOKE=false \
    CARGO_HTTP_SSL_VERSION_CHECK=false \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Build statically linked executable using musl
RUN rustup target add x86_64-unknown-linux-musl
# Use musl-gcc as the C compiler for the musl target
ENV CC_x86_64_unknown_linux_musl=musl-gcc
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl

# Apply extreme binary optimization and compression
# 1. Strip all symbols
RUN strip -s target/x86_64-unknown-linux-musl/release/quantum_scanner

# 2. Apply UPX compression if enabled
RUN if [ "$ULTRA_MINIMAL" = "true" ]; then \
        echo "Applying ultra-minimal UPX compression..." && \
        stdbuf -o0 -e0 upx -vvv --best --ultra-brute target/x86_64-unknown-linux-musl/release/quantum_scanner || \
        echo "UPX ultra compression failed, continuing without it."; \
    elif [ "$ENABLE_UPX" = "true" ]; then \
        echo "Applying standard UPX compression..." && \
        stdbuf -o0 -e0 upx -vvv --best target/x86_64-unknown-linux-musl/release/quantum_scanner || \
        echo "UPX compression failed, continuing without it."; \
    else \
        echo "Skipping UPX compression"; \
    fi

# 3. Display final file size for verification
RUN ls -lh target/x86_64-unknown-linux-musl/release/quantum_scanner

# Use a minimal base for the final image
FROM scratch

# Copy the built binary from builder stage
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/quantum_scanner /quantum_scanner

# Set entrypoint
ENTRYPOINT ["/quantum_scanner"] 