#!/bin/sh
set -eu -o pipefail

TCP_PORTS="80,443,5060,5061,6100,8080,8443"
UDP_PORTS="53,123,5060,5061,6100,1200,30000,40000"

LOG_FILE="${DATA_OUTPUT_DIR}/logs/${CONTAINER_START_TS}_${EPDG_MCC}_${EPDG_MNC}_conn_check_server.log"

echo "Network info:\n" >> $LOG_FILE
ip a >> $LOG_FILE
echo "\n\n" >> $LOG_FILE

python3 /root/connectivity-check/server/conn_check_server.py \
  --tcp-ports "${TCP_PORTS}" \
  --udp-ports "${UDP_PORTS}" \
  --host "::" 2>&1 | \
  tee -a $LOG_FILE
