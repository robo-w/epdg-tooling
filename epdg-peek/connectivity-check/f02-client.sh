#!/bin/sh
set -eu -o pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <server-host>"
    exit 1
fi

TCP_PORTS="80,443,5060,5061,6100,8080,8443"
UDP_PORTS="53,123,5060,5061,6100,1200,30000,40000"

LOG_FILE="${DATA_OUTPUT_DIR}/logs/${CONTAINER_START_TS}_${EPDG_MCC}_${EPDG_MNC}_conn_check_client.log"
CSV_FILE="${DATA_OUTPUT_DIR}/logs/${CONTAINER_START_TS}_${EPDG_MCC}_${EPDG_MNC}_conn_check_result.csv"

echo "Network info:\n" >> $LOG_FILE
ip a >> $LOG_FILE
echo "\n\n" >> $LOG_FILE

python3 /root/connectivity-check/client/conn_check_client.py \
  --tcp-ports "${TCP_PORTS}" \
  --udp-ports "${UDP_PORTS}" \
  --host "$1" > $CSV_FILE 2>> $LOG_FILE

echo ""
echo "Results:\n"
cat $CSV_FILE
