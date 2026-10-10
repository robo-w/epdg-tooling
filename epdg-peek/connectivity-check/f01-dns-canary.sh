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

LOG_FILE="${DATA_OUTPUT_DIR}/logs/${CONTAINER_START_TS}_${EPDG_MCC}_${EPDG_MNC}_dns-canary.log"
STATIC_CANARY_STRING="JBUWK4RANPB3M3TOORSSASLIOJSSAV3FOJRHK3THEBZWK2LOHLYJ7KVH"

if [ -z "${IMS_DNS_IP+x}" ]; then
  echo "\n${FMT_CYAN}No DNS servers received from ePDG - skipping test.${FMT_RESET}"
else
  echo "\n${FMT_CYAN}Trying to perform DNS lookup...${FMT_RESET}"
  INFO_CANARY_STRING=$(echo -n "MCC:${EPDG_MCC} MNC:${EPDG_MNC}")
  INFO_CANARY_STRING_ENCODED=$(printf "%-20s" "${INFO_CANARY_STRING}" | base32)
  DATE_CANARY_STRING=$(date -Is)
  DATE_CANARY_STRING_ENCODED=$(printf "%-30s" "${DATE_CANARY_STRING}" | base32)

  if [ -z "${DNS_CANARY_DOMAIN+x}" ]; then
    LOOKUP_DOMAIN="google.com"
  else
    LOOKUP_DOMAIN="${DATE_CANARY_STRING_ENCODED}.${INFO_CANARY_STRING_ENCODED}.${STATIC_CANARY_STRING}.${DNS_CANARY_DOMAIN}"
  fi

  echo "  Looking up: '${LOOKUP_DOMAIN}'"
  echo "  Using DNS server: ${IMS_DNS_IP}"
  echo "  Performing lookup..."

  if LOOKUP_RESULT=$(ip netns exec ims dig +short +timeout=2 "${LOOKUP_DOMAIN}" @${IMS_DNS_IP} | grep -v ";; "); then
    if [ -z "${LOOKUP_RESULT}" ]; then
      echo "  DNS lookup returned ${FMT_GREEN}empty response${FMT_RESET}"
      log_to_stats_file "external-dns-lookup" "${LOOKUP_DOMAIN}" "empty_response"
    else
      echo "  DNS lookup ${FMT_RED}succeeded${FMT_RESET}: ${LOOKUP_RESULT}"
      log_to_stats_file "external-dns-lookup" "${LOOKUP_DOMAIN}" "${LOOKUP_RESULT}"
    fi
  else
    echo "  DNS lookup ${FMT_GREEN}failed${FMT_RESET}."
    log_to_stats_file "external-dns-lookup" "${LOOKUP_DOMAIN}" "no_response"
  fi
fi



