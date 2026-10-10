#!/bin/sh
set -eu -o pipefail

FMT_RED='\033[1;31m'
FMT_GREEN='\033[1;32m'
FMT_YELLOW='\033[1;33m'
FMT_CYAN='\033[1;36m'
FMT_RESET='\033[0m'

NETNS_PREFIX="ip netns exec ims"
LOG_FILE="${DATA_OUTPUT_DIR}/logs/${CONTAINER_START_TS}_${EPDG_MCC}_${EPDG_MNC}_sip-register-auth.log"
SIP_REGISTER_CMD="${NETNS_PREFIX} python3 /root/sip-python/sip_register.py"
SIP_AUTH_CMD="python3 /root/sip-python/sip_auth_sim.py"

if [ -z "${AUTH_STATE_FILE+x}" ]; then
  echo "\n${FMT_YELLOW}Warning: AUTH_STATE_FILE environment variable is not set.${FMT_RESET} Using default value: /root/auth_state.json"
  AUTH_STATE_FILE="/root/auth_state.json"
fi

log_to_stats_file() {
  # $1 = module name
  # $2 = parameters
  # $3 = result
  echo "${CONTAINER_START_TS},$(date -In | sed -e 's/,/./'),${EPDG_MCC},${EPDG_MNC},${EPDG_IP},$1,$2,$3" >> ${TESTRUN_STATS_FILE}
}

send_register_request() {
  if REGISTER_RESPONSE=$( ${SIP_REGISTER_CMD} --cseq=${CSEQ_COUNTER} --call-id="${SIP_CALL_ID}" --auth-file="${AUTH_STATE_FILE}" 2>> "${LOG_FILE}"); then
    echo "${FMT_GREEN}Sent${FMT_RESET}"
    CSEQ_COUNTER=$((CSEQ_COUNTER + 1))

    echo -n "  Authentication challenge received? "
    if echo "${REGISTER_RESPONSE}" | grep -q "SIP/2.0 401"; then
      echo "${FMT_GREEN}Yes${FMT_RESET}"
      log_to_stats_file "sip-register-auth" "register-challenge" "accepted"
    else
      RESPONSE_LINE=$(echo "${REGISTER_RESPONSE}" | head -n 1 | sed -e 's/[\r\n]*//g')
      echo "${FMT_RED}No${FMT_RESET} - Response line: '${RESPONSE_LINE}'"
      log_to_stats_file "sip-register-auth" "register-challenge" "rejected"
      exit 1
    fi
  else
    echo "${FMT_RED}No response${FMT_RESET}"
    log_to_stats_file "sip-register-auth" "register-challenge" "request_failed"
    exit 1
  fi
}


echo "\n${FMT_CYAN}Authenticating with SIP REGISTER...${FMT_RESET}"

# Skip IPsec transport mode, if requested
if [ ! -z ${SIP_REGISTER_SKIP_SEC_AGREE+x} ]; then
  echo "  skipping 'sec-agree' aka 'phase 3' aka 'IPsec transport mode' for SIP REGISTER"
  SIP_REGISTER_CMD="${SIP_REGISTER_CMD} --cipher=suppress-header"
  SIP_AUTH_CMD="${SIP_AUTH_CMD} --skip-ipsec"
fi

set +e
SIP_CALL_ID=$(tr -dc A-Za-z0-9 < /dev/urandom | head -c 23)
set -e

CSEQ_COUNTER=1

echo -n "  Sending request with default cipher proposal... "
send_register_request

echo -n "  Performing authentication... "
if SIM_AUTH_RESPONSE=$( ${SIP_AUTH_CMD} --auth-file="${AUTH_STATE_FILE}" 2>> "${LOG_FILE}"); then
  echo "${FMT_GREEN}Done${FMT_RESET}"
  log_to_stats_file "sip-register-auth" "register-auth" "success"
elif [ $? -eq 20 ]; then
  echo "${FMT_YELLOW}AUTS${FMT_RESET}"
  log_to_stats_file "sip-register-auth" "register-auth" "resync_requested"

  echo -n "  Sending request with AUTS response to get a new challenge... "
  send_register_request

  echo -n "  Performing authentication... "
  if SIM_REAUTH_RESPONSE=$( ${SIP_AUTH_CMD} --auth-file="${AUTH_STATE_FILE}" 2>> "${LOG_FILE}"); then
    echo "${FMT_GREEN}Done${FMT_RESET}"
    log_to_stats_file "sip-register-auth" "register-auth" "success-after-resync"
  else
    echo "${FMT_RED}Failed${FMT_RESET}"
    log_to_stats_file "sip-register-auth" "register-auth" "failed-after-resync"
    exit 1
  fi
else
  echo "${FMT_RED}Failed${FMT_RESET}"
  log_to_stats_file "sip-register-auth" "register-auth" "failed"
  exit 1
fi

echo -n "  Dumping keys to esp_sa for Wireshark... "
if ${NETNS_PREFIX} ip xfrm state | awk -f /root/sip-python/ipsec-to-ws.awk >> "${DATA_OUTPUT_DIR}/wireshark/esp_sa"; then
  echo "${FMT_GREEN}Done${FMT_RESET}"
else
  echo "${FMT_RED}Failed${FMT_RESET}"
  log_to_stats_file "sip-register-auth" "register-auth" "wireshark_dump_failed"
fi

echo -n "  Sending request with authentication response... "
if REGISTER_RESPONSE=$( ${SIP_REGISTER_CMD} --cseq=${CSEQ_COUNTER} --call-id="${SIP_CALL_ID}" --auth-file="${AUTH_STATE_FILE}" 2>> "${LOG_FILE}"); then
  echo "${FMT_GREEN}Sent${FMT_RESET}"
  CSEQ_COUNTER=$((CSEQ_COUNTER + 1))

  echo -n "  Authentication success received? "
  if echo "${REGISTER_RESPONSE}" | grep -q "SIP/2.0 200"; then
    echo "${FMT_GREEN}Yes${FMT_RESET}"
    log_to_stats_file "sip-register-auth" "register-response" "authenticated"
  else
    RESPONSE_LINE=$(echo "${REGISTER_RESPONSE}" | head -n 1 | sed -e 's/[\r\n]*//g')
    echo "${FMT_RED}No${FMT_RESET} - Response line: '${RESPONSE_LINE}'"
    log_to_stats_file "sip-register-auth" "register-response" "rejected"
    exit 1
  fi
else
  echo "${FMT_RED}No response${FMT_RESET}"
  log_to_stats_file "sip-register-auth" "register-response" "request_failed"
  exit 1
fi

