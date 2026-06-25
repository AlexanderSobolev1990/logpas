#!/usr/bin/env bash
set -euo pipefail

sudo apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libsodium-dev \
    libssl-dev \
    libboost-program-options-dev

if ! command -v xclip >/dev/null 2>&1 &&
   ! command -v xsel >/dev/null 2>&1 &&
   ! command -v wl-copy >/dev/null 2>&1; then
    sudo apt-get install -y xclip ||
    sudo apt-get install -y xsel ||
    sudo apt-get install -y wl-clipboard ||
    echo "warning: install xclip, xsel or wl-clipboard manually for --cp/--cl"
fi
