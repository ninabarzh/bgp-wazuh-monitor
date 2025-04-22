# detectors/ssh-bruteforce/Dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    libjsoncpp-dev \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy source
WORKDIR /app
COPY src/ ./src/
COPY ../shared/wazuh_client.hpp ./shared/

# Build
RUN g++ -std=c++20 -o detector \
    src/detector.cpp \
    -ljsoncpp

# Runtime config
ENV CHECK_INTERVAL=60
ENV USE_MOCK=true

CMD ["./detector", "--mock"]