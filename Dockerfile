ARG RUST_VERSION=1
ARG DEBIAN_VERSION=bookworm

FROM --platform=$BUILDPLATFORM docker.io/tonistiigi/xx AS xx
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS base
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS toolchain

# Prevent deletion of apt cache
RUN rm -f /etc/apt/apt.conf.d/docker-clean

# Match Rustc version as close as possible
# rustc -vV
ARG LLVM_VERSION=20
# ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

# Install repo tools
# Line one: compiler tools
# Line two: curl, for downloading binaries
# Line three: for xx-verify
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y \
    pkg-config make jq \
    curl git software-properties-common \
    file

# LLVM packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    curl https://apt.llvm.org/llvm.sh > llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh ${LLVM_VERSION} && \
    rm llvm.sh

# Create symlinks for LLVM tools
RUN <<EOF
    set -o xtrace
    # clang
    ln -s /usr/bin/clang-${LLVM_VERSION} /usr/bin/clang
    ln -s "/usr/bin/clang++-${LLVM_VERSION}" "/usr/bin/clang++"
    # lld
    ln -s /usr/bin/ld64.lld-${LLVM_VERSION} /usr/bin/ld64.lld
    ln -s /usr/bin/ld.lld-${LLVM_VERSION} /usr/bin/ld.lld
    ln -s /usr/bin/lld-${LLVM_VERSION} /usr/bin/lld
    ln -s /usr/bin/lld-link-${LLVM_VERSION} /usr/bin/lld-link
    ln -s /usr/bin/wasm-ld-${LLVM_VERSION} /usr/bin/wasm-ld
EOF

# Developer tool versions
# renovate: datasource=github-releases depName=cargo-bins/cargo-binstall
ENV BINSTALL_VERSION=1.12.3
# renovate: datasource=github-releases depName=psastras/sbom-rs
ENV CARGO_SBOM_VERSION=0.9.1
# renovate: datasource=crate depName=lddtree
ENV LDDTREE_VERSION=0.3.7

# Install unpackaged tools
RUN <<EOF
    set -o xtrace
    curl --retry 5 -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
    cargo binstall --no-confirm cargo-sbom --version $CARGO_SBOM_VERSION
    cargo binstall --no-confirm lddtree --version $LDDTREE_VERSION
EOF

# Set up xx (cross-compilation scripts)
COPY --from=xx / /
ARG TARGETPLATFORM

# Install libraries linked by the binary
# xx-* are xx-specific meta-packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    xx-apt-get install -y \
    xx-c-essentials xx-cxx-essentials pkg-config \
    libssl-dev libsqlite3-dev

# Set up Rust toolchain
WORKDIR /app
# COPY ./rust-toolchain.toml .
RUN rustc --version \
    && rustup target add $(xx-cargo --print-target-triple)

# Build binary
# We disable incremental compilation to save disk space, as it only produces a minimal speedup for this case.
RUN echo "CARGO_INCREMENTAL=0" >> /etc/environment

# Configure pkg-config
RUN <<EOF
    set -o xtrace
    echo "PKG_CONFIG_LIBDIR=/usr/lib/$(xx-info)/pkgconfig" >> /etc/environment
    echo "PKG_CONFIG=/usr/bin/$(xx-info)-pkg-config" >> /etc/environment
    echo "PKG_CONFIG_ALLOW_CROSS=true" >> /etc/environment
EOF

# Configure cc to use clang version
RUN <<EOF
    set -o xtrace
    echo "CC=clang" >> /etc/environment
    echo "CXX=clang++" >> /etc/environment
EOF

# Cross-language LTO
RUN <<EOF
    set -o xtrace
    echo "CFLAGS=-flto" >> /etc/environment
    echo "CXXFLAGS=-flto" >> /etc/environment
    # Linker is set to target-compatible clang by xx
    echo "RUSTFLAGS='-Clinker-plugin-lto -Clink-arg=-fuse-ld=lld'" >> /etc/environment
EOF

# Apply CPU-specific optimizations if TARGET_CPU is provided
ARG TARGET_CPU=
RUN <<EOF
  set -o allexport
  set -o xtrace
  . /etc/environment
  if [ -n "${TARGET_CPU}" ]; then
    echo "CFLAGS='${CFLAGS} -march=${TARGET_CPU}'" >> /etc/environment
    echo "CXXFLAGS='${CXXFLAGS} -march=${TARGET_CPU}'" >> /etc/environment
    echo "RUSTFLAGS='${RUSTFLAGS} -C target-cpu=${TARGET_CPU}'" >> /etc/environment
  fi
EOF

# Prepare output directories
RUN mkdir /out

FROM toolchain AS builder


# Get source
COPY . .

ARG TARGETPLATFORM

# Verify environment configuration
RUN xx-cargo --print-target-triple

# Build the binary
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/app/target,id=cargo-target-${TARGETPLATFORM} \
    bash <<'EOF'
    set -o allexport
    set -o xtrace
    . /etc/environment
    TARGET_DIR=($(cargo metadata --no-deps --format-version 1 | \
            jq -r ".target_directory"))
    mkdir /out/sbin
    PACKAGE=jwt-service
    xx-cargo build --locked --release \
        -p $PACKAGE;
    BINARIES=($(cargo metadata --no-deps --format-version 1 | \
        jq -r ".packages[] | select(.name == \"$PACKAGE\") | .targets[] | select( .kind | map(. == \"bin\") | any ) | .name"))
    for BINARY in "${BINARIES[@]}"; do
        echo $BINARY
        xx-verify $TARGET_DIR/$(xx-cargo   --print-target-triple)/release/$BINARY
        cp $TARGET_DIR/$(xx-cargo --print-target-triple)/release/$BINARY /out/sbin/$BINARY
    done
EOF

# Generate Software Bill of Materials (SBOM)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    bash <<'EOF'
    set -o xtrace
    mkdir /out/sbom
    typeset -A PACKAGES
    for BINARY in /out/sbin/*; do
        BINARY_BASE=$(basename ${BINARY})
        package=$(cargo metadata --no-deps --format-version 1 | jq -r ".packages[] | select(.targets[] | select( .kind | map(. == \"bin\") | any ) | .name == \"$BINARY_BASE\") | .name")
        if [ -z "$package" ]; then
            continue
        fi
        PACKAGES[$package]=1
    done
    for PACKAGE in $(echo ${!PACKAGES[@]}); do
        echo $PACKAGE
        cargo sbom --cargo-package $PACKAGE > /out/sbom/$PACKAGE.spdx.json
    done
EOF

# Extract dynamically linked dependencies
RUN <<EOF
    set -o xtrace
    mkdir /out/libs
    mkdir /out/libs-root
    for BINARY in /out/sbin/*; do
        lddtree "$BINARY" | awk '{print $(NF-0) " " $1}' | sort -u -k 1,1 | awk '{print "install", "-D", $1, (($2 ~ /^\//) ? "/out/libs-root" $2 : "/out/libs/" $2)}' | xargs -I {} sh -c {}
    done
EOF

FROM scratch

WORKDIR /

# Copy root certs for tls into image
# You can also mount the certs from the host
# --volume /etc/ssl/certs:/etc/ssl/certs:ro
COPY --from=base /etc/ssl/certs /etc/ssl/certs
# --volume /usr/share/zoneinfo:/usr/share/zoneinfo:ro
COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo

# Copy our build
COPY --from=builder /out/sbin/ /sbin/
# Copy SBOM
COPY --from=builder /out/sbom/ /sbom/

# Copy dynamic libraries to root
COPY --from=builder /out/libs-root/ /
COPY --from=builder /out/libs/ /usr/lib/

# Inform linker where to find libraries
ENV LD_LIBRARY_PATH=/usr/lib

EXPOSE 3000

CMD ["/sbin/jwt_service_cli"]
