# detectors/bgp-hijack/Dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libjsoncpp-dev \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy source
WORKDIR /app
COPY src/ ./src/
COPY ../shared/wazuh_client.hpp ./shared/

# Build
RUN g++ -std=c++20 -o detector \
    src/detector.cpp \
    -lcurl -ljsoncpp

# Runtime config
ENV CHECK_INTERVAL=300
ENV USE_MOCK=true

# Override in docker-compose.yml
CMD ["./detector", "--mock"]