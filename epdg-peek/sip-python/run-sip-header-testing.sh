#!/bin/sh
set -eu -o pipefail

FMT_CYAN='\033[1;36m'
FMT_RESET='\033[0m'

NETNS_PREFIX="ip netns exec ims"

LOG_FILE="${DATA_OUTPUT_DIR}/logs/${CONTAINER_START_TS}_${EPDG_MCC}_${EPDG_MNC}_sip-sender.log"
SIP_SENDER_CMD="${NETNS_PREFIX} python3 /root/sip-python/sip_sender.py"

if [ $# -gt 0 ] && echo "$1" | grep -Eq '^(tel|sip):[+]?[0-9a-zA-Z]+@?[a-zA-Z0-9.;=]*$'; then
  SIP_SENDER_CMD="${SIP_SENDER_CMD} --target $1"
else
  echo "Usage: $0 \"<target-number>\""
  echo "  <target-number> should be in the format tel:+1234567890 or sip:+1234567890@example.com;user=phone"
  exit 1
fi

echo "\n${FMT_CYAN}Running SIP sender...${FMT_RESET}"
echo "  Target: '$1'"

${SIP_SENDER_CMD} --method INVITE 2>> "${LOG_FILE}"

