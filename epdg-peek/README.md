# epdg-peek

`epdg-peek` is a Docker based image to test various security configurations in
the IMS network of a provider.
Despite the name, the tool peeks into the ePDG and beyond, for example to the
P-CSCF for SIP configuration and the general network setup in the EPC.

## Architecture

The main part of the tool is Docker container based on the
[Osmocom IMS Client](https://osmocom.org/projects/foss-ims-client).

## Usage

* Install Docker.
* Connect a **PCSC compatible smartcard reader** to the host.
* Insert a **valid SIM card** into the smartcard reader.
* Start the script `utils/run-container.sh`.
  * If you use a smartcard reader not yet listed in the script, add your VID:PID there.
* The container starts - here the magic happens:
  * The modified `pySim` script reads the network settings from the SIM card
  * The strongswan settings are automatically adapted based on the SIM card
  * The ePDG servers are queried via DNS
  * If at least one server is present, it is used as target for `strongSwan` with the `ims` profile
  * The IPsec connection is authenticated via the SIM card, and the IMS servers are requested
  * Basic connectivity scripts are started: Ping to internet, ping P-CSCF
* If successful, the container presents an interactive shell to perform further checks

## Customization

* `utils` contains an `example.env` file for customization of the startup, for example:
  * Pinning the connection to a specific ePDG IP
  * Skipping the default scripts
  * Running custom scripts after startup
  * Selecting specific IKE or ESP proposals

## Build image

```bash
docker build -t ghcr.io/robo-w/epdg-peek:v1.0.0-nightly .
```

## Run manually

**Deprecated**

```bash
docker run -it --rm \
  --device=/dev/bus/usb/003/002:/dev/bus/usb/003/002 \
  --name epdg-test \
  -v ./epdg-logs:/root/epdg-logs \
  --cap-add CAP_SYS_ADMIN --cap-add NET_ADMIN \
  --security-opt apparmor=unconfined \
  --security-opt systempaths=unconfined \
  ghcr.io/robo-w/epdg-peek:latest
```

⚠️ For the network setting changes it is necessary to disable certain Docker security features (see command above).
