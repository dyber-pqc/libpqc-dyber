# libpqc-dyber container image, published to ghcr.io/dyber-pqc/libpqc-dyber
# by .github/workflows/release.yml on every release tag.
#
# The image holds the installed library (shared and static), its headers
# and the pqc-cli tool under /usr/local. Use it directly:
#
#   docker run --rm ghcr.io/dyber-pqc/libpqc-dyber:0.3.1 pqc-cli algorithms
#
# or copy the library into your own image:
#
#   COPY --from=ghcr.io/dyber-pqc/libpqc-dyber:0.3.1 /usr/local/ /usr/local/

FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake ninja-build gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The test suite runs in CI before a release is tagged; the KAT suites
# alone take several minutes, so the image build skips them.
RUN cmake -S . -B /build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DPQC_BUILD_SHARED=ON -DPQC_BUILD_STATIC=ON -DPQC_BUILD_CLI=ON \
      -DPQC_BUILD_TESTS=OFF -DPQC_BUILD_BENCHMARKS=OFF \
 && cmake --build /build \
 && cmake --install /build \
 && /usr/local/bin/pqc-cli version

FROM debian:bookworm-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="libpqc-dyber" \
      org.opencontainers.image.description="Post-quantum cryptography library in C: ML-KEM, ML-DSA, SLH-DSA, HQC, BIKE, FrodoKEM, LMS, XMSS and hybrids" \
      org.opencontainers.image.source="https://github.com/dyber-pqc/libpqc-dyber" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /usr/local/ /usr/local/
COPY LICENSE-APACHE LICENSE-MIT /usr/local/share/doc/libpqc-dyber/
RUN ldconfig
CMD ["pqc-cli", "--help"]
