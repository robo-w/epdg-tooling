#!/bin/sh

FMT_CYAN='\033[1;36m'
FMT_RESET='\033[0m'

NETNS_PREFIX="ip netns exec ims"

LOG_FILE="${DATA_OUTPUT_DIR}/logs/${CONTAINER_START_TS}_${EPDG_MCC}_${EPDG_MNC}_sip-responder.log"
SIP_RESPONDER_CMD="${NETNS_PREFIX} python3 /root/sip-python/sip_responder.py"

echo "\n${FMT_CYAN}Starting SIP responder...${FMT_RESET}"
echo "  Press Ctrl+C to stop the SIP responder and exit the script."

${SIP_RESPONDER_CMD} 2>> "${LOG_FILE}"
