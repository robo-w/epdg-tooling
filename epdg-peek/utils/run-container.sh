#!/bin/bash

IMAGE_NAME="ghcr.io/robo-w/epdg-peek:latest"
CONTAINER_NAME_PREFIX="epdg-tester-0"

# Add your VID/PID of a PC/SC card reader here, if different.
CARD_READER_VID_PID="058f:9540"

if [ -z "${CARD_READER_INDEX}" ] || [[ ! "${CARD_READER_INDEX}" =~ ^[1-8]$ ]]; then
  echo "Using default card reader index '1'."
  CARD_READER_INDEX=1
fi

CONTAINER_NAME="${CONTAINER_NAME_PREFIX}${CARD_READER_INDEX}"

# Search for matching AU9540 Smartcard Reader
SELECTED_CARD_READER=$(lsusb -d ${CARD_READER_VID_PID} | \
  sort | \
  sed "${CARD_READER_INDEX}!d" | \
  sed -e 's|Bus |/dev/bus/usb/|' -e 's| Device |/|' -e 's/: ID .*//')

if [ -z "${SELECTED_CARD_READER}" ]; then
  echo "No AU9540 Smartcard Reader found."
  exit 1
fi

mkdir -p "${HOME}"/epdg-logs

if docker version >/dev/null 2>&1; then
  echo "Starting ePDG container with Smartcard Reader at '${SELECTED_CARD_READER}'..."
  ADDITIONAL_OPTS=""
  if [ -n "${EPDG_ENV_FILE}" ]; then
    ADDITIONAL_OPTS="${ADDITIONAL_OPTS} --env-file ${EPDG_ENV_FILE}"
  fi

  docker run \
    -it \
    --rm \
    --device="${SELECTED_CARD_READER}":"${SELECTED_CARD_READER}" \
    --name "${CONTAINER_NAME}" \
    -v "${HOME}"/epdg-logs:/root/epdg-logs \
    --cap-add CAP_SYS_ADMIN \
    --cap-add NET_ADMIN \
    --security-opt apparmor=unconfined \
    --security-opt systempaths=unconfined \
    ${ADDITIONAL_OPTS} \
    "${IMAGE_NAME}" \
    ${AUTO_TEST_SCRIPT:-}
else
  echo "Docker is not installed or accessible."
  exit 1
fi
