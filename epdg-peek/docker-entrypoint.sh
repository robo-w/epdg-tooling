#!/bin/dash

log_to_stats_file() {
  # $1 = module name
  # $2 = parameters
  # $3 = result
  echo "${START_TS},$(date -In | sed -e 's/,/./'),${EPDG_MCC},${EPDG_MNC},${EPDG_IP},$1,$2,$3" >> "${TESTRUN_STATS_FILE}"
}

stop_strongswan() {
  echo "\n${FMT_CYAN}Stopping strongSwan...${FMT_RESET}"
  if ipsec stop; then
    echo "  Done."
  else
    echo "  strongSwan was not running."
  fi
}

stop_tcpdump() {
  TCPDUMP_PID=$(cat /root/tcpdump.pid 2>/dev/null)
  if [ -n "${TCPDUMP_PID}" ]; then
    echo "\n${FMT_CYAN}Stopping tcpdump (PID: ${TCPDUMP_PID})...${FMT_RESET}"

    sleep 1
    kill "${TCPDUMP_PID}" 2>/dev/null
    rm -f /root/tcpdump.pid
    echo "  Waiting for tcpdump to terminate..."
    wait "${TCPDUMP_PID}" 2>/dev/null
    echo "  Done."
  else
    echo "\n${FMT_CYAN}No tcpdump PID file found, skipping tcpdump termination${FMT_RESET}"
  fi
}

graceful_exit() {
  set +e
  # Remove traps
  trap - TERM INT EXIT

  echo "\n\n${FMT_RED}Encountered an error during script, performing graceful exit${FMT_RESET}"

  stop_strongswan
  stop_tcpdump

  echo "\n"
}

exit_wrapper() {
  graceful_exit
  exit "$1"
}

# Use TERM and INT for dash, SIGTERM and SIGINT for bash
trap 'graceful_exit' EXIT
trap '{ exit_wrapper 1; }' TERM INT

prepare_folder() {
  if [ -z ${DATA_OUTPUT_DIR+x} ] || [ -z "${DATA_OUTPUT_DIR}" ]; then
    export DATA_OUTPUT_DIR="/root/epdg-logs/${CURRENT_DAY}"
  fi

  mkdir -p "${DATA_OUTPUT_DIR}"/wireshark
  mkdir -p "${DATA_OUTPUT_DIR}"/logs
  mkdir -p "${DATA_OUTPUT_DIR}"/tcpdump

  STARTUP_LOG="${DATA_OUTPUT_DIR}/logs/${START_TS}_docker-startup.log"
}

start_pcscd() {
  # Start pcscd in the container.
  # If this step fails, check if the host has a PC/SC daemon running and stop it first.
  echo "\n${FMT_CYAN}Starting pcscd...${FMT_RESET}"
  if pcscd --disable-polkit >> "${STARTUP_LOG}" 2>&1; then
    echo "  ${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "  ${FMT_RED}FAILED${FMT_RESET}"
    exit_wrapper 1
  fi
}

read_usim_properties() {
  # Reading parameters from inserted SIM card. Script fails on any error:
  #   - missing SIM card
  #   - incompatible smartcard
  echo "\n${FMT_CYAN}Reading IMSI from SIM card via pySim...${FMT_RESET}"
  local PYSIM_IMSI_LOG="${DATA_OUTPUT_DIR}/logs/${START_TS}_pySim-imsi.log"
  echo "${FMT_PURPLE}  Log file: ${PYSIM_IMSI_LOG}${FMT_RESET}"
  echo -n "  Reading smartcard... "
  if /root/.venv/pysim/bin/python3 /root/pysim/pySim-readIMSI.py -p 0 > "${PYSIM_IMSI_LOG}" 2>&1; then
    echo "  ${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "  ${FMT_RED}FAILED${FMT_RESET}"
    echo "  Check log file for details."
    exit_wrapper 2
  fi

  # Parse the returned parameters, write them to disk and variables
  echo "\n${FMT_CYAN}Parsing IMSI, MCC and MNC from results:${FMT_RESET}"
  export EPDG_IMSI=$(grep "IMSI: " "${PYSIM_IMSI_LOG}" | \
    sed -e 's/IMSI: //' | \
    tee /root/imsi.txt)
  PARSED_MCC=$(grep "  MCC: " "${PYSIM_IMSI_LOG}" | \
    sed -e 's/  MCC: //' | \
    tee /root/mcc.txt)
  PARSED_MNC=$(grep "  MNC: " "${PYSIM_IMSI_LOG}" | \
    sed -e 's/  MNC: //' | \
    tee /root/mnc.txt)

  # MSISDN is informational only, and not present on all SIM cards.
  # It is NOT used in any later configuration steps.
  INFO_MSISDN=$(grep "MSISDN" "${PYSIM_IMSI_LOG}" | \
    sed -e 's/  MSISDN //')

  echo "  IMSI: ${EPDG_IMSI}"
  echo "${FMT_GREEN}   MCC: ${PARSED_MCC}${FMT_RESET}"
  echo "${FMT_GREEN}   MNC:    ${PARSED_MNC}${FMT_RESET}"
  echo ""
  echo "  ${INFO_MSISDN}"


  if [ -z ${PINNED_MCC+x} ] || [ -z "${PINNED_MCC}" ]; then
    export EPDG_MCC="${PARSED_MCC}"
  elif echo "${PINNED_MCC}" | grep -qE '^[0-9]{3}$'; then
    export EPDG_MCC="${PINNED_MCC}"
    echo "\n${FMT_YELLOW}  Using pinned MCC: ${EPDG_MCC}${FMT_RESET}"
    echo "${PINNED_MCC}" > /root/mcc.txt
  else
    echo "\n${FMT_RED}ERROR: Provided PINNED_MCC '${PINNED_MCC}' is not a valid MCC!${FMT_RESET}\n"
    exit_wrapper 1
  fi

  if [ -z ${PINNED_MNC+x} ] || [ -z "${PINNED_MNC}" ]; then
    export EPDG_MNC="${PARSED_MNC}"
  elif echo "${PINNED_MNC}" | grep -qE '^[0-9]{2}$'; then
    export EPDG_MNC="${PINNED_MNC}"
    echo "\n${FMT_YELLOW}  Using pinned MNC: ${EPDG_MNC}${FMT_RESET}"
    echo "${PINNED_MNC}" > /root/mnc.txt
  else
    echo "\n${FMT_RED}ERROR: Provided PINNED_MNC '${PINNED_MNC}' is not a valid MNC!\n    Currently only two-digit MNCs are supported.${FMT_RESET}\n"
    exit_wrapper 1
  fi
}

query_epdg_ip() {
  if [ -z ${EPDG_IP+x} ] || [ -z "${EPDG_IP}" ]; then
    # Query ePDG IP from DNS.
    echo "\n${FMT_CYAN}Querying ePDG IPs from DNS...${FMT_RESET}"
    local EPDG_DNS_NAME="epdg.epc.mnc0${EPDG_MNC}.mcc${EPDG_MCC}.pub.3gppnetwork.org"
    local EPDG_IP_LIST=$(dig +short "${EPDG_DNS_NAME}" | grep -v ";; ")
    export EPDG_IP=$(echo "${EPDG_IP_LIST}" | head -n 1)
    if [ -z "${EPDG_IP}" ] || [ "${EPDG_IP}" = "127.0.0.1" ]; then
      echo "${FMT_RED}  ERROR: No ePDG IPs found for ${EPDG_DNS_NAME}${FMT_RESET}"
      exit_wrapper 3
    fi
    echo "  ePDG IPs for '${EPDG_DNS_NAME}':"
    echo "${FMT_GREEN}    ${EPDG_IP}${FMT_RESET}"
    echo "${EPDG_IP_LIST}" | tail -n +2 | sed -e 's/^/    /'
  elif echo "${EPDG_IP}" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
    echo "\n${FMT_CYAN}Using provided ePDG IPv4:${FMT_RESET} ${FMT_GREEN}${EPDG_IP}${FMT_RESET}"
  elif echo "${EPDG_IP}" | grep -qE '^[0-9a-fA-F:]+$'; then
    echo "\n${FMT_CYAN}Using provided ePDG IPv6:${FMT_RESET} ${FMT_GREEN}${EPDG_IP}${FMT_RESET}"
  else
    echo "\n${FMT_RED}ERROR: Provided ePDG IP '${EPDG_IP}' is not a valid IP address!${FMT_RESET}\n"
    exit_wrapper 1
  fi
}

update_strongswan_config_templates() {
  # Replace the placeholders in the strongSwan template config file.
  echo "\n${FMT_CYAN}Writing parameters to strongSwan config file...${FMT_RESET}"
  sed -i -e "s/###IMSI###/${EPDG_IMSI}/g" \
    -e "s/###MCC###/${EPDG_MCC}/g" \
    -e "s/###MNC###/${EPDG_MNC}/g" \
    -e "s/###LOCAL_IP###/${OWN_DOCKER_IP}/g" \
    -e "s/###EPDG_IP###/${EPDG_IP}/g" \
    /usr/local/etc/swanctl/conf.d/epdg.conf
  echo "  Updated '/usr/local/etc/swanctl/conf.d/epdg.conf'"
  sed -i -e "s/###START_TS###/${START_TS}/g" \
    -e "s|###LOG_DIR###|${DATA_OUTPUT_DIR}/logs|g" \
    -e "s/###MCC###/${EPDG_MCC}/g" \
    -e "s/###MNC###/${EPDG_MNC}/g" \
    /usr/local/etc/strongswan.d/charon-logging.conf
  echo "  Updated '/usr/local/etc/strongswan.d/charon-logging.conf'"
  sed -i -e "s|###DATA_DIR###|${DATA_OUTPUT_DIR}|g" \
    /usr/local/etc/strongswan.d/charon/save-keys.conf
  echo "  Updated '/usr/local/etc/strongswan.d/charon/save-keys.conf'"

  if [ ! -z ${INSECURE_DH+x} ]; then
    sed -i -e "s/# ###3GPP_v12.2.0_INSECURE_DH### //" \
      /usr/local/etc/swanctl/conf.d/epdg.conf
    echo "  Enabled 3GPP TS 33.210 v12.2.0 IKE proposal with ${FMT_PURPLE}insecure DH groups${FMT_RESET} in '/usr/local/etc/swanctl/conf.d/epdg.conf'"
  elif [ ! -z ${CUSTOM_IKE_PROPOSAL+x} ]; then
    sed -i -e "s/###CUSTOM_IKE_PROPOSAL###/proposals = ${CUSTOM_IKE_PROPOSAL}/g" \
      /usr/local/etc/swanctl/conf.d/epdg.conf
    echo "  Using custom IKE proposals: '${FMT_PURPLE}${CUSTOM_IKE_PROPOSAL}${FMT_RESET}' in '/usr/local/etc/swanctl/conf.d/epdg.conf'"
  else
    sed -i -e "s/# ###3GPP_v12.2.0### //" \
      /usr/local/etc/swanctl/conf.d/epdg.conf
    echo "  Enabled 3GPP TS 33.210 v12.2.0 IKE proposal in '/usr/local/etc/swanctl/conf.d/epdg.conf'"
    echo "  Use INSECURE_DH=1 to enable outdated DH groups for key exchange."
  fi

  if [ ! -z ${ESP_WEAKEST_FIRST+x} ]; then
    sed -i -e "s/# ###ESP_WEAK_FIRST### //" \
      /usr/local/etc/swanctl/conf.d/epdg.conf
    echo "  Enabled 3GPP ${FMT_PURPLE}weakest-preferred${FMT_RESET} ESP proposal in '/usr/local/etc/swanctl/conf.d/epdg.conf'"
  elif [ ! -z ${ESP_INSECURE+x} ]; then
    sed -i -e "s/# ###ESP_INSECURE### //" \
      /usr/local/etc/swanctl/conf.d/epdg.conf
    echo "  Enabled ESP proposal with ${FMT_RED}NULL-cipher${FMT_RESET} in '/usr/local/etc/swanctl/conf.d/epdg.conf'"
    echo "  ${FMT_RED}[!] WARNING: VERY INSECURE configuration, use with care!${FMT_RESET}"
  elif [ ! -z ${CUSTOM_ESP_PROPOSAL+x} ]; then
    sed -i -e "s/###CUSTOM_ESP_PROPOSAL###/esp_proposals = ${CUSTOM_ESP_PROPOSAL}/g" \
      /usr/local/etc/swanctl/conf.d/epdg.conf
    echo "  Using custom ESP proposals: '${FMT_PURPLE}${CUSTOM_ESP_PROPOSAL}${FMT_RESET}' in '/usr/local/etc/swanctl/conf.d/epdg.conf'"
  else
    sed -i -e "s/# ###ESP_SECURE_FIRST### //" \
      /usr/local/etc/swanctl/conf.d/epdg.conf
    echo "  Enabled secure-preferred ESP proposal in '/usr/local/etc/swanctl/conf.d/epdg.conf'"
    echo "    Use ESP_WEAKEST_FIRST=1 to enable weakest-preferred, or ESP_INSECURE=1 to allow null-cipher for encryption."
  fi


  if [ -z "${EPDG_TUN_IPV4+x}" ]; then
    sed -i -e "s/# ###TS_IPv6### //g" \
      -e 's/# ###VIRT_IPv6s### //g' \
      /usr/local/etc/swanctl/conf.d/epdg.conf
    echo "  Enabled ${FMT_PURPLE}IPv6${FMT_RESET} traffic selectors in '/usr/local/etc/swanctl/conf.d/epdg.conf'"
  else
    sed -i -e "s/# ###TS_IPv4### //g" \
      -e 's/# ###VIRT_IPv4s### //g' \
      /usr/local/etc/swanctl/conf.d/epdg.conf
    echo "  Enabled ${FMT_PURPLE}IPv4${FMT_RESET} traffic selectors in '/usr/local/etc/swanctl/conf.d/epdg.conf'"
  fi
}

prepare_network_interfaces() {
  # Run strongSwan setup steps
  echo "\n${FMT_CYAN}Running network setup steps for strongSwan...${FMT_RESET}"
  if ip netns list | grep -q ims; then
    echo "${FMT_RED}  ERROR: Namespace 'ims' already exists!${FMT_RESET}"
    exit_wrapper 1
  fi

  echo -n "  Creating namespace... "
  if ip netns add ims >> "${STARTUP_LOG}" 2>&1; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "${FMT_RED}FAILED${FMT_RESET}"
    exit_wrapper 1
  fi

  echo -n "  Creating tunnel interface tun23... "
  if ip link add tun23 type xfrm if_id 23 >> "${STARTUP_LOG}" 2>&1 && ip link set tun23 netns ims >> "${STARTUP_LOG}" 2>&1; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "${FMT_RED}FAILED${FMT_RESET}"
    exit_wrapper 1
  fi

  echo -n "  Starting tun23 interface... "
  if ip netns exec ims ip link set tun23 up >> ${STARTUP_LOG} 2>&1; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "${FMT_RED}FAILED${FMT_RESET}"
    exit_wrapper 1
  fi

  if [ -z "${EPDG_TUN_IPV4+x}" ]; then
    echo -n "  Configure IPv6 routing in ims namespace... "
    if ip netns exec ims ip route add ::/0 dev tun23 >> ${STARTUP_LOG} 2>&1; then
      echo "${FMT_GREEN}OK${FMT_RESET}"
      export EPDG_TUN_IP_FAMILY="IPv6"
    else
      echo "${FMT_RED}FAILED${FMT_RESET}"
      exit_wrapper 1
    fi
  else
    echo -n "  Configure IPv4 routing in ims namespace... "
    if ip netns exec ims ip route add 0.0.0.0/0 dev tun23 >> ${STARTUP_LOG} 2>&1; then
      echo "${FMT_GREEN}OK${FMT_RESET}"
      export EPDG_TUN_IP_FAMILY="IPv4"
    else
      echo "${FMT_RED}FAILED${FMT_RESET}"
      exit_wrapper 1
    fi
  fi

  echo -n "  Adding loopback interface to ims namespace... "
  if ip netns exec ims ip link set lo up >> ${STARTUP_LOG} 2>&1; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "${FMT_RED}FAILED${FMT_RESET}"
    exit_wrapper 1
  fi

  local DISABLE_IPSEC_POLICY_CMD="echo 1 > /proc/sys/net/ipv6/conf/tun23/disable_policy"
  echo -n "  Disable IPsec policy on tun23 interface to enable received IMS IPs... "
  echo "${DISABLE_IPSEC_POLICY_CMD}" | ip netns exec ims sh
  echo "${FMT_GREEN}OK${FMT_RESET}"
}

start_packet_capture() {
  if [ -z ${SKIP_PACKET_CAPTURE+x} ]; then
    # Starting packet capture in background
    echo "\n${FMT_CYAN}Starting packet capture in background...${FMT_RESET}"
    echo "  Use SKIP_PACKET_CAPTURE=1 to skip packet capture."
    CAPTURE_FILE="${DATA_OUTPUT_DIR}/tcpdump/${START_TS}_${EPDG_MCC}_${EPDG_MNC}_capture.pcap"
    echo "${FMT_PURPLE}  Capture file: ${CAPTURE_FILE}${FMT_RESET}"
    echo -n "  Starting tcpdump... "
    nohup tcpdump -i any -w "${CAPTURE_FILE}" > /root/tcpdump.out 2>&1 &
    echo "$!" > /root/tcpdump.pid

    # Short wait, to ensure that first packets are captured
    sleep 1
    echo "${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "\n${FMT_CYAN}Skipping packet capture due to SKIP_PACKET_CAPTURE environment variable${FMT_RESET}"
  fi
}

start_strongswan_daemon() {
  # Starting strongSwan
  echo ""
  echo "${FMT_CYAN}Starting strongSwan...${FMT_RESET}"
  echo "${FMT_PURPLE}  Log file: ${DATA_OUTPUT_DIR}/logs/${START_TS}_${EPDG_MCC}_${EPDG_MNC}_strongswan.log${FMT_RESET}"
  echo -n "  Starting strongSwan daemon... "
  if ipsec start >> ${STARTUP_LOG} 2>&1; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "${FMT_RED}FAILED${FMT_RESET}"
    exit_wrapper 4
  fi

  # Daemon starts in background, wait a second to ensure swanctl commands are working
  sleep 1

  echo -n "  Loading credential configurations... "
  if swanctl --load-creds >> ${STARTUP_LOG} 2>&1; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "${FMT_RED}FAILED${FMT_RESET}"
    exit_wrapper 4
  fi

  echo -n "  Loading connection configurations... "
  local SWAN_LOAD_CONNS=$(swanctl --load-conns)
  if echo "${SWAN_LOAD_CONNS}" | grep -q "successfully loaded 1 connections"; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
  else
    echo "${FMT_RED}FAILED${FMT_RESET}"
    echo "  swanctl output:"
    echo "${SWAN_LOAD_CONNS}"
    exit_wrapper 4
  fi
}

initiate_named_child_sa() {
  if [ -z "$1" ]; then
    local CHILD_SA_NAME="ims"
  else
    local CHILD_SA_NAME="$1"
  fi

  echo -n "  Initiating CHILD_SA '${CHILD_SA_NAME}'... "
  SWAN_INIT=$(swanctl --initiate --child "${CHILD_SA_NAME}" --timeout 10 2>&1)
  if echo "${SWAN_INIT}" | grep -q "initiate completed successfully"; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
    return 0
  else
    echo "${FMT_RED}FAILED${FMT_RESET}"
#    echo "  swanctl output:"
#    echo "${SWAN_INIT}"
    return 1
  fi
}

terminate_named_child_sa() {
  if [ -z "$1" ]; then
    local CHILD_SA_NAME="ims"
  else
    local CHILD_SA_NAME="$1"
  fi

  echo -n "  Terminating CHILD_SA '${CHILD_SA_NAME}'... "
  local SWAN_TERMINATE=$(swanctl --terminate --child "${CHILD_SA_NAME}" --timeout 5 2>&1)
  if echo "${SWAN_TERMINATE}" | grep -q "terminate completed successfully"; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
    return 0
  else
    echo "${FMT_YELLOW}FAILED${FMT_RESET}"
    return 1
  fi
}

terminate_ike() {
  echo -n "  Terminating IKE_SA 'ims'... "
  local SWAN_TERMINATE=$(swanctl --terminate --ike ims --force --timeout 5 2>&1)
  if echo "${SWAN_TERMINATE}" | grep -q "terminate completed successfully"; then
    echo "${FMT_GREEN}OK${FMT_RESET}"
    return 0
  else
    echo "${FMT_YELLOW}FAILED${FMT_RESET}"
    return 1
  fi
}

testcase_f11_child_sa() {
  if [ -z "$1" ]; then
    echo "${FMT_RED}ERROR: No CHILD_SA name provided to testcase_f11_child_sa()${FMT_RESET}"
    exit_wrapper 1
  else
    local CHILD_SA_NAME="$1"
  fi

  if initiate_named_child_sa "${CHILD_SA_NAME}"; then
    log_to_stats_file "Testcase_f11_child_sa" "${CHILD_SA_NAME}" "success"

    SELECTED_PROPOSAL_IKE=$(echo "${SWAN_INIT}" | \
      grep "selected proposal: IKE" | \
      head -n 1 | \
      sed -e 's/^.* selected proposal: IKE://')

    SELECTED_PROPOSAL_ESP=$(echo "${SWAN_INIT}" | \
      grep "selected proposal: ESP" | \
      head -n 1 | \
      sed -e 's/^.* selected proposal: ESP://')

    log_to_stats_file "SelectedIKEProposal" "" "\"${SELECTED_PROPOSAL_IKE}\""
    log_to_stats_file "SelectedESPProposal" "" "\"${SELECTED_PROPOSAL_ESP}\""

    sleep 3

    terminate_named_child_sa "${CHILD_SA_NAME}"
  else
    if echo "${SWAN_INIT}" | grep -q " N(NO_PROP) "; then
      log_to_stats_file "Testcase_f11_child_sa" "${CHILD_SA_NAME}" "proposal_rejected"
    else
      log_to_stats_file "Testcase_f11_child_sa" "${CHILD_SA_NAME}" "failed"
    fi

    terminate_named_child_sa "${CHILD_SA_NAME}"
  fi

  if echo "${SWAN_INIT}" | grep -q " N((41112)) "; then
    log_to_stats_file "Testcase_f11_emergency_support" "${CHILD_SA_NAME}" "support_announced"
  fi

  # Just to make sure, that no-response runs did not leave a hanging IKE_SA behind.
  terminate_ike
}

initiate_child_sa() {
  # Initiate the ePDG connection
  echo "${FMT_CYAN}Initiating ePDG connection...${FMT_RESET}"

  if initiate_named_child_sa "ims"; then
    echo ""
  else
    exit_wrapper 4
  fi

  export IMS_PCSCF_IP_LIST=$(echo "${SWAN_INIT}" | \
    grep "received P-CSCF server" | \
    sed -e 's/^.*received P-CSCF server IP //')
  export IMS_PCSCF_IP=$(echo "${IMS_PCSCF_IP_LIST}" | \
    head -n 1)

  export IPSEC_LOCAL_IP=$(echo "${SWAN_INIT}" | \
    grep "installing new virtual" | \
    head -n 1 | \
    sed -e 's/^.* installing new virtual IP //')

  if echo "${SWAN_INIT}" | grep -q "installing DNS server"; then
    export IMS_DNS_IP_LIST=$(echo "${SWAN_INIT}" | \
      grep "installing DNS server" | \
      sed -e 's/^.* installing DNS server //' -e 's| to .*||')
    export IMS_DNS_IP=$(echo "${IMS_DNS_IP_LIST}" | head -n 1)
  fi

  SELECTED_PROPOSAL_IKE=$(echo "${SWAN_INIT}" | \
    grep "selected proposal: IKE" | \
    head -n 1 | \
    sed -e 's/^.* selected proposal: IKE://')

  SELECTED_PROPOSAL_ESP=$(echo "${SWAN_INIT}" | \
    grep "selected proposal: ESP" | \
    head -n 1 | \
    sed -e 's/^.* selected proposal: ESP://')

  echo "  Installed local IP: ${FMT_PURPLE}${IPSEC_LOCAL_IP}${FMT_RESET}"
  echo "${IMS_PCSCF_IP_LIST}" | \
    sed -e 's/^/  P-CSCF IP: /g'
  if [ ! -z "${IMS_DNS_IP_LIST+x}" ]; then
    echo "${IMS_DNS_IP_LIST}" | \
      sed -e 's/^/  DNS IP:    /g'
  fi

  echo "  Selected IKE proposal: ${FMT_PURPLE}${SELECTED_PROPOSAL_IKE}${FMT_RESET}"
  if echo "${SELECTED_PROPOSAL_IKE}" | grep -q -e "MODP_768" -e "MODP_1024"; then
    echo "    ${FMT_RED}Insecure DH group!${FMT_RESET}"
  fi
  if echo "${SELECTED_PROPOSAL_IKE}" | grep -q -e "NULL" -e "DES"; then
    echo "    ${FMT_RED}Insecure encryption!${FMT_RESET}"
  fi
  if echo "${SELECTED_PROPOSAL_IKE}" | grep -q -e "SHA1"; then
    echo "    ${FMT_RED}Insecure SHA1 hash function!${FMT_RESET}"
  fi

  echo "  Selected ESP proposal: ${FMT_PURPLE}${SELECTED_PROPOSAL_ESP}${FMT_RESET}"
  if echo "${SELECTED_PROPOSAL_ESP}" | grep -q -e "NULL" -e "DES"; then
    echo "    ${FMT_RED}Insecure encryption!${FMT_RESET}"
  fi
  if echo "${SELECTED_PROPOSAL_ESP}" | grep -q -e "SHA1" -e "MD5"; then
    echo "    ${FMT_RED}Insecure hash function!${FMT_RESET}"
  fi
}

set -Eu -o pipefail

# General preperation steps
# =========================

START_TS=$(date -In | sed -e 's/://g' -e 's/,/_/g' -e 's/+0000/Z/')
CURRENT_DAY=$(date -Id)
export CONTAINER_START_TS="${START_TS}"

FMT_RED='\033[1;31m'
FMT_GREEN='\033[1;32m'
FMT_YELLOW='\033[1;33m'
FMT_PURPLE='\033[1;35m'
FMT_CYAN='\033[1;36m'
FMT_RESET='\033[0m'

prepare_folder
start_pcscd
read_usim_properties
query_epdg_ip

export TESTRUN_STATS_FILE="${DATA_OUTPUT_DIR}/logs/${START_TS}_${EPDG_MCC}_${EPDG_MNC}__stats.csv"

if [ -z ${SKIP_STATS_FILE_HEADER+x} ]; then
  echo "StartTimestamp,LoggedTimestamp,MCC,MNC,ePDG_IP,Module,Parameters,Result" > "${TESTRUN_STATS_FILE}"
else
  touch "${TESTRUN_STATS_FILE}"
fi

log_to_stats_file "usimImsi" "" "${EPDG_IMSI}"

# Read own IP address, assuming that default docker IP addresses are used.
echo "\n${FMT_CYAN}Reading own IP address...${FMT_RESET}"
OWN_DOCKER_IP=$(hostname -i)
echo "  Own IP address: ${OWN_DOCKER_IP}"

update_strongswan_config_templates
prepare_network_interfaces
log_to_stats_file "UsedIpFamilyInTunnel" "" "${EPDG_TUN_IP_FAMILY}"

start_packet_capture

start_strongswan_daemon
log_to_stats_file "strongSwanStartup" "" "success"


if [ -z ${TESTCASE_F11_FULL+x} ]; then
  initiate_child_sa
else
  echo "\n${FMT_CYAN}Running full ESP proposal probing...${FMT_RESET}"
  echo "  Attempts are delayed by 35 seconds between each proposal, to avoid false errors from rate limiting"

  testcase_f11_child_sa "ims-f11-null"
  echo "  ...sleeping"; sleep 5
  testcase_f11_child_sa "ims-f11-blowfish"
  echo "  ...sleeping"; sleep 5
  testcase_f11_child_sa "ims-f11-3des"
  echo "  ...sleeping"; sleep 5
  testcase_f11_child_sa "ims-f11-hmac-md5"
  echo "...sleeping"; sleep 5
  testcase_f11_child_sa "ims-f11-hmac-sha1"

  echo "${FMT_CYAN}F11 ESP testing finished, shutting down...${FMT_RESET}\n"

  stop_strongswan
  stop_tcpdump

  trap - TERM INT EXIT
  exit 0
fi

log_to_stats_file "LocalIp" "" "${IPSEC_LOCAL_IP}"
for pcscf_ip in ${IMS_PCSCF_IP_LIST}; do
  log_to_stats_file "P-CSCF" "" "${pcscf_ip}"
done
log_to_stats_file "SelectedIKEProposal" "" "\"${SELECTED_PROPOSAL_IKE}\""
log_to_stats_file "SelectedESPProposal" "" "\"${SELECTED_PROPOSAL_ESP}\""

echo ""
echo "${FMT_CYAN}✅ ePDG connection setup successful${FMT_RESET}"
echo ""

if [ -z ${SKIP_PCAP_BEAUTIFY+x} ]; then
  echo "\n${FMT_CYAN}PCAP-beautification${FMT_RESET}"
  echo "  Use SKIP_PCAP_BEAUTIFY=1 to run scripts immediately."
  echo -n "  Waiting two seconds to receive all unsolicited packets... "
  sleep 2
  echo "${FMT_GREEN}OK${FMT_RESET}"
fi

if [ -z ${SKIP_DEFAULT_SCRIPTS+x} ]; then
  echo "\nRunning default connectivity check scripts. Use SKIP_DEFAULT_SCRIPTS=1 to skip these scripts."
  /root/connectivity-check/ping-all-pcscf-servers.sh
  /root/connectivity-check/f01-ping-external.sh
  /root/sip-python/run-register-fingerprint.sh
else
  echo "\n${FMT_CYAN}Skipping default connectivity check scripts due to SKIP_DEFAULT_SCRIPTS environment variable${FMT_RESET}"
fi

export AUTH_STATE_FILE="/root/auth_state.json"

# Perform SIP registration if variable is set
if [ ! -z ${SIP_REGISTER+x} ]; then
  echo "\n...waiting 5 seconds to get PC/SC card back from strongSwan"
  sleep 5
  /root/sip-python/run-register-auth.sh
fi


if [ "$#" -gt 0 ]; then
  echo "\n${FMT_CYAN}Starting user-provided command${FMT_RESET}..."
  echo "  Running command: '$*'"
  exec "$@"
else
  echo ""
  echo "Example commands to continue:"
  echo "  Check connectivity to IMS: ${FMT_PURPLE}ip netns exec ims ping ${IMS_PCSCF_IP}${FMT_RESET}"
  echo "    or use alias: ${FMT_PURPLE}ims-netns ping ${IMS_PCSCF_IP}${FMT_RESET}"
  echo "  Probe SIP server: ${FMT_PURPLE}ip netns exec ims telnet ${IMS_PCSCF_IP} 5060${FMT_RESET}"
  echo "  Run P-CSCF ping checks: ${FMT_PURPLE}/root/connectivity-check/f01-ping-external.sh${FMT_RESET}"
  echo "  Run external ping checks: ${FMT_PURPLE}/root/connectivity-check/f01-ping-external.sh${FMT_RESET}"
  echo "  Run server for connectivity checks: ${FMT_PURPLE}ip netns exec ims /root/connectivity-check/f02-server.sh${FMT_RESET}"
  echo "  Run client for connectivity checks: ${FMT_PURPLE}ip netns exec ims /root/connectivity-check/f02-client.sh <REMOTE_IPv6>${FMT_RESET}"
  echo "  Run SIP registration test: ${FMT_PURPLE}ip netns exec ims python3 sip-python/sip_register.py${FMT_RESET}"
  echo "  Graceful termination: ${FMT_PURPLE}swanctl --terminate --child ims${FMT_RESET}"
  echo "  Shutdown script: ${FMT_PURPLE}~/stop-ipsec.sh${FMT_RESET}"
  echo ""

  echo "${FMT_CYAN}No command provided, starting interactive shell...${FMT_RESET}\n"
  echo "${FMT_PURPLE}  📞 Happy hacking! 🤓${FMT_RESET}\n"
  exec /bin/bash -l
fi
