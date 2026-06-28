FROM golang:1.25-bookworm

# Install MinGW-w64 cross compilers and build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        mingw-w64 \
        g++-mingw-w64 \
        gcc \
        g++ \
        make \
        build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
