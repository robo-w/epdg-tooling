#!/bin/sh

FMT_RED='\033[1;31m'
FMT_GREEN='\033[1;32m'
FMT_YELLOW='\033[1;33m'
FMT_CYAN='\033[1;36m'
FMT_RESET='\033[0m'


NETNS_PREFIX="ip netns exec ims"
AUTH_STATE_FILE="/root/auth_state.json"

BURN_TIMESTAMP=$(date -Is | sed -e 's/://g' -e 's/,/_/g' -e 's/+0000/Z/')

echo "\n🔥 ${FMT_RED}Burning Phase 3 of IPsec...${FMT_RESET}"

echo -n "  Removing xfrm states... "
${NETNS_PREFIX} ip xfrm state flush
echo "${FMT_GREEN}Done${FMT_RESET}"

echo -n "  Removing xfrm policies... "
${NETNS_PREFIX} ip xfrm policy flush
echo "${FMT_GREEN}Done${FMT_RESET}"

echo -n "  Removing authentication state file... "
mv "${AUTH_STATE_FILE}" "${AUTH_STATE_FILE}.${BURN_TIMESTAMP}.bak"
echo "${FMT_GREEN}Done${FMT_RESET}"

echo "\n${FMT_CYAN}Phase 3 removed.${FMT_RESET}\n"
