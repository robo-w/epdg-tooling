#!/bin/sh
set -eu -o pipefail

FMT_RED='\033[1;31m'
FMT_GREEN='\033[1;32m'
FMT_CYAN='\033[1;36m'
FMT_RESET='\033[0m'

log_to_stats_file() {
  # $1 = module name
  # $2 = parameters
  # $3 = result
  echo "${CONTAINER_START_TS},$(date -In | sed -e 's/,/./'),${EPDG_MCC},${EPDG_MNC},${EPDG_IP},$1,$2,$3" >> ${TESTRUN_STATS_FILE}
}

echo "\n${FMT_CYAN}Pinging external servers...${FMT_RESET}"

if [ "${EPDG_TUN_IP_FAMILY}" = "IPv4" ]; then
  TARGET_IP=$(dig +short google.com A | grep -v ";; " | head -n 1)
  PING_OPTS="-4"
  log_to_stats_file "external-ping-A" "google.com" "${TARGET_IP}"
else
  TARGET_IP=$(dig +short google.com AAAA | grep -v ";; " | head -n 1)
  PING_OPTS="-6"
  log_to_stats_file "external-ping-AAAA" "google.com" "${TARGET_IP}"
fi

echo -n "  Pinging 'google.com' at ${TARGET_IP}... "
PING_RESULT=$(ip netns exec ims ping ${PING_OPTS} -n -O -c 2 -W 1 "${TARGET_IP}" 2>&1 || echo "0 received")
if echo "${PING_RESULT}" | grep -q "0 received"; then
  echo "${FMT_GREEN}No answer (Good!)${FMT_RESET}"
  log_to_stats_file "external-ping" "${TARGET_IP}" "no_answer"
else
  echo "${FMT_RED}External connectivity!${FMT_RESET}"
  log_to_stats_file "external-ping" "${TARGET_IP}" "ok"
fi

