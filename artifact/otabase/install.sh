#!/bin/bash
set -e  

echo "[1/3] Installing dependencies..."
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libfftw3-dev \
    libmbedtls-dev \
    libboost-program-options-dev \
    libconfig++-dev \
    libsctp-dev

echo "[2/3] Building OTABase..."
if [ ! -d "build" ]; then
    mkdir build
fi
cd build
cmake ..
make -j$(nproc)

echo "[3/3] Build complete!"