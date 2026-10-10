#!/bin/sh
set -eu -o pipefail

FMT_RED='\033[1;31m'
FMT_GREEN='\033[1;32m'
FMT_YELLOW='\033[1;33m'
FMT_CYAN='\033[1;36m'
FMT_RESET='\033[0m'

LOG_FILE="${DATA_OUTPUT_DIR}/logs/${CONTAINER_START_TS}_${EPDG_MCC}_${EPDG_MNC}_sip-register-fingerprint.log"
SIP_REGISTER_CMD="ip netns exec ims python3 /root/sip-python/sip_register.py"

log_to_stats_file() {
  # $1 = module name
  # $2 = parameters
  # $3 = result
  echo "${CONTAINER_START_TS},$(date -In | sed -e 's/,/./'),${EPDG_MCC},${EPDG_MNC},${EPDG_IP},$1,$2,$3" >> ${TESTRUN_STATS_FILE}
}

send_probing_register() {
  # $1 = cipher proposal
  # $2 = cseq
  # $3 = call-id
  echo -n "  Sending request with '$1' proposal... "
  if SIP_RESPONSE=$( ${SIP_REGISTER_CMD} --cipher="$1" --cseq="$2" --call-id="$3" 2>> "${LOG_FILE}"); then
    echo "${FMT_GREEN}Sent${FMT_RESET}"
    echo -n "  Does server accept '$1' proposal? "
    if echo "${SIP_RESPONSE}" | grep -q "SIP/2.0 401"; then
      echo "${FMT_RED}Yes${FMT_RESET}"
      log_to_stats_file "sip-register-fingerprint" "$1" "accepted"
    elif echo "${SIP_RESPONSE}" | grep -q "SIP/2.0 421"; then
      echo "${FMT_GREEN}Rejected${FMT_RESET}"
      log_to_stats_file "sip-register-fingerprint" "$1" "rejected"

      if echo "${SIP_RESPONSE}" | grep -q "Invalid security-client header and IPsecAKA is force on "; then
        echo "    'security-client' warning in error response looks ${FMT_GREEN}Huawei specific${FMT_RESET}"
        log_to_stats_file "sip-register-fingerprint-vendor" "Huawei_security-client_header" "found"
      fi
    elif echo "${SIP_RESPONSE}" | grep -q "SIP/2.0 403"; then
      echo "${FMT_GREEN}Forbidden${FMT_RESET}"
      if echo "${SIP_RESPONSE}" | grep -q "X-ZTE-Cause: \"CSCF-"; then
        echo "    ZTE does not accept more than one REGISTER with the same Call-ID"
      fi
      log_to_stats_file "sip-register-fingerprint" "$1" "rejected-forbidden"
    else
      RESPONSE_LINE=$(echo "${SIP_RESPONSE}" | head -n 1 | sed -e 's/[\r\n]*//g')
      echo "${FMT_GREEN}No${FMT_RESET} - Response line: '${RESPONSE_LINE}'"
      log_to_stats_file "sip-register-fingerprint" "$1" "rejected-unknown"
    fi

    if echo "${SIP_RESPONSE}" | grep -q "X-ZTE-Cause: "; then
      echo "    'X-ZTE-Cause' header in error response looks ${FMT_GREEN}ZTE specific${FMT_RESET}"
      log_to_stats_file "sip-register-fingerprint-vendor" "ZTE_X-ZTE-Cause_header" "found"
      ZTE_DEVICE_FOUND=1
    fi

    if echo "${SIP_RESPONSE}" | grep -q "P-Debug-Info: "; then
      echo "    'P-Debug-Info' header in error response - vendor unknown"
      log_to_stats_file "sip-register-fingerprint-vendor" "P-Debug-Info_header" "found"
    fi
  else
    echo "\n${FMT_RED}No response${FMT_RESET}"
    log_to_stats_file "sip-register-fingerprint" "$1" "request_failed"
  fi
}

echo "\n${FMT_CYAN}Try basic fingerprinting of P-CSCF via SIP REGISTER...${FMT_RESET}"

set +e
SIP_CALL_ID=$(tr -dc A-Za-z0-9 < /dev/urandom | head -c 23)
set -e

# TODO: In order to fully support Huawei fingerprinting, create a new Call-ID for each request,
#         but ONLY if Huawei equipment was detected. New Call-IDs are out-of-spec!

send_probing_register "f11-encr-null" 1 "${SIP_CALL_ID}"
sleep 2
send_probing_register "f11-encr-des" 2 "${SIP_CALL_ID}"
sleep 2
send_probing_register "f11-auth-md5" 3 "${SIP_CALL_ID}"
sleep 2
send_probing_register "f11-invalid-auth-null" 4 "${SIP_CALL_ID}"
sleep 2
send_probing_register "suppress-header" 5 "${SIP_CALL_ID}"

# Let's be nice to the P-CSCF
sleep 2

echo -n "  Sending request with AES-CBC cipher proposal... "
if AES_CBC_CIPHER_RESPONSE=$( ${SIP_REGISTER_CMD} --cipher=aes-cbc --cseq=6 --call-id="${SIP_CALL_ID}" 2>> "${LOG_FILE}"); then
  echo "${FMT_GREEN}Sent${FMT_RESET}"

  echo -n "  Does server accept AES-CBC proposal? "
  if echo "${AES_CBC_CIPHER_RESPONSE}" | grep -q "SIP/2.0 401"; then
    echo "${FMT_GREEN}Yes${FMT_RESET}"
    log_to_stats_file "sip-register-fingerprint" "aes-cbc" "accepted"
  elif echo "${AES_CBC_CIPHER_RESPONSE}" | grep -q "SIP/2.0 421"; then
    echo "${FMT_RED}Rejected${FMT_RESET}"
    log_to_stats_file "sip-register-fingerprint" "aes-cbc" "rejected"

    if echo "${AES_CBC_CIPHER_RESPONSE}" | grep -q "Invalid security-client header and IPsecAKA is force on "; then
      echo "    'security-client' warning in error response looks ${FMT_GREEN}Huawei specific${FMT_RESET}"
      log_to_stats_file "sip-register-fingerprint-vendor" "Huawei_security-client_header" "found"
    fi
  else
    RESPONSE_LINE=$(echo "${AES_CBC_CIPHER_RESPONSE}" | head -n 1 | sed -e 's/[\r\n]*//g')
    echo "${FMT_RED}No${FMT_RESET} - Response line: '${RESPONSE_LINE}'"
    log_to_stats_file "sip-register-fingerprint" "aes-cbc" "rejected-unknown"
  fi
else
  echo "\n${FMT_RED}No response${FMT_RESET}"
  log_to_stats_file "sip-register-fingerprint" "aes-cbc" "request_failed"
fi

sleep 2

# Out-of-spec, but Huawei (and ZTE?) make troubles otherwise: create a new Call-ID here.
echo -n "  Sending request with default cipher proposals... "
if ALL_CIPHERS_RESPONSE=$( ${SIP_REGISTER_CMD} --cipher=default --cseq=42 2>> "${LOG_FILE}"); then
  echo "${FMT_GREEN}Sent${FMT_RESET}"

  echo -n "  Does server accept any cipher proposal of 'default'? "
  if echo "${ALL_CIPHERS_RESPONSE}" | grep -q "SIP/2.0 401"; then
    echo "${FMT_GREEN}Yes${FMT_RESET}"
    log_to_stats_file "sip-register-fingerprint" "default" "accepted"
  elif echo "${ALL_CIPHERS_RESPONSE}" | grep -q "SIP/2.0 400 Bad Request" && echo "${ALL_CIPHERS_RESPONSE}" | grep -q "Sip key parameter invalid"; then
    echo "${FMT_RED}Huawei-Bug${FMT_RESET}"
    log_to_stats_file "sip-register-fingerprint" "default" "rejected_huawei-call-id-reuse"
    echo "    rejected Call-ID re-use looks ${FMT_GREEN}Huawei specific${FMT_RESET}"
    log_to_stats_file "sip-register-fingerprint-vendor" "Huawei_s-cscf_call-id-reuse_rejected" "found"
  else
    RESPONSE_LINE=$(echo "${ALL_CIPHERS_RESPONSE}" | head -n 1 | sed -e 's/[\r\n]*//g')
    echo "${FMT_RED}No?${FMT_RESET} - Response line: '${RESPONSE_LINE}'"
    echo "  Please check the logs. Probably it is rejected due to an unrelated issue."
    log_to_stats_file "sip-register-fingerprint" "default" "rejected-unknown"
  fi

  TO_HEADER_PARAMS=$(echo "${ALL_CIPHERS_RESPONSE}" | grep -i "To: " | sed -e 's/To:.*<.*>//' -e 's/[\r\n]*//g')
  echo "  Received params in To header: '${TO_HEADER_PARAMS}'"
  if echo "${TO_HEADER_PARAMS}" | grep -q ";tag=ztesip"; then
    echo "    tag in To header looks ${FMT_GREEN}ZTE specific${FMT_RESET}"
    log_to_stats_file "sip-register-fingerprint-vendor" "ZTE_ztesip" "found"
    ZTE_DEVICE_FOUND=1
  fi
  if echo "${TO_HEADER_PARAMS}" | grep -q ";tag=mavodi"; then
    echo "    tag in To header looks ${FMT_GREEN}Mavenir specific${FMT_RESET}"
    log_to_stats_file "sip-register-fingerprint-vendor" "Mavenir_mavodi" "found"
  fi
else
  echo "\n${FMT_RED}No response${FMT_RESET}"
  log_to_stats_file "sip-register-fingerprint" "default" "request_failed"
fi


if [ "${ZTE_DEVICE_FOUND:-0}" -eq 1 ]; then
  echo "\n${FMT_CYAN}Running ZTE-specific probing${FMT_RESET}"
  echo "  Sending multiple requests with fixed Call-IDs to fetch a few more nonces in the responses"

  send_probing_register "f11-encr-null" 90 "FixedCallIdForZTEprobing"
  sleep 2
  send_probing_register "f11-encr-null" 90 "SecondFixedCallId"
  sleep 2
  send_probing_register "f11-encr-null" 90 "FixedCallIdForZTEprobing"
fi
