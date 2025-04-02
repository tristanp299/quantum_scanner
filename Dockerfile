# Multi-stage Dockerfile for building a static Quantum Scanner
FROM rust:slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y libssl-dev pkg-config

# Create build directory
WORKDIR /build

# Copy source code
COPY . .

# Build statically linked executable using musl
RUN rustup target add x86_64-unknown-linux-musl
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl

# Use a minimal base for the final image
FROM scratch

# Copy the built binary from builder stage
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/quantum_scanner /quantum_scanner

# Set entrypoint
ENTRYPOINT ["/quantum_scanner"] 