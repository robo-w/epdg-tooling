#!/bin/dash

FMT_CYAN='\033[1;36m'
FMT_RESET='\033[0m'

echo "\n${FMT_CYAN}Terminating strongSwan child 'ims'...${FMT_RESET}"
if swanctl --terminate --child ims; then
  echo "  Done."
else
  echo "  No child 'ims' found to terminate."
fi

echo "\n${FMT_CYAN}Stopping strongSwan...${FMT_RESET}"
if ipsec stop; then
  echo "  Done."
else
  echo "  strongSwan was not running."
fi

TCPDUMP_PID=$(cat /root/tcpdump.pid 2>/dev/null)
if [ -n "${TCPDUMP_PID}" ]; then
  echo "\n${FMT_CYAN}Stopping tcpdump (PID: ${TCPDUMP_PID})...${FMT_RESET}"
  kill "${TCPDUMP_PID}" 2>/dev/null
  rm -f /root/tcpdump.pid
  echo "  Waiting for tcpdump to terminate..."
  wait "${TCPDUMP_PID}" 2>/dev/null
  echo "  Done."
else
  echo "\n${FMT_CYAN}No tcpdump PID file found, skipping tcpdump termination${FMT_RESET}"
fi

# TODO: gracefully stop pcscd

echo "\n${FMT_CYAN}✅ All done.${FMT_RESET}\n"

