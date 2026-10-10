#!/bin/sh
set -eu -o pipefail

FMT_RED='\033[1;31m'
FMT_GREEN='\033[1;32m'
FMT_CYAN='\033[1;36m'
FMT_RESET='\033[0m'

echo "\n${FMT_CYAN}Pinging P-CSCF servers...${FMT_RESET}"
echo "${IMS_PCSCF_IP_LIST}" | while IFS= read -r p_cscf_ip; do
  echo -n "  Pinging ${p_cscf_ip}... "
  PING_RESULT=$(ip netns exec ims ping -6 -n -O -c 2 -W 1 "${p_cscf_ip}" 2>&1 || echo "0 received")
  if echo "${PING_RESULT}" | grep -q "0 received"; then
    echo "${FMT_RED}No answer${FMT_RESET}"
    echo "${CONTAINER_START_TS},$(date -In | sed -e 's/,/./'),${EPDG_MCC},${EPDG_MNC},${EPDG_IP},P-CSCF-ping,${p_cscf_ip},no_answer" >> ${TESTRUN_STATS_FILE}
  else
    echo "${FMT_GREEN}OK${FMT_RESET}"
    echo "${PING_RESULT}" | \
      grep "icmp_seq" | \
      sed -e "s/^.*time=/${CONTAINER_START_TS},$(date -In | sed -e 's/,/./'),${EPDG_MCC},${EPDG_MNC},${EPDG_IP},P-CSCF-ping,${p_cscf_ip},/g" >> ${TESTRUN_STATS_FILE}
  fi

done

