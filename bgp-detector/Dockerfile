FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libbgpstream-dev \
    libjsoncpp-dev \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/bgp_detector.cpp .

RUN g++ -std=c++20 -o bgp_detector bgp_detector.cpp -lcurl -lbgpstream

CMD ["./bgp_detector"]