#!/usr/bin/env bash

# 2026, original script by Philipp Frenzel
# 2026, modified by Robert Wittek

set -eux
set -o pipefail

BASE_DIR="${HOME}/epdg-logs/$(date -Id)/wireshark"
mkdir -p "${BASE_DIR}"

stdbuf -oL -eL adb shell su -c 'ip xfrm monitor SA' | \
  tee -a "${BASE_DIR}/xfrm.txt" | \
  awk -Winteractive -f ~/epdg-tooling/sa-capture-adb/ipsec-to-ws.awk | \
  tee -a "${BASE_DIR}/esp_sa"
