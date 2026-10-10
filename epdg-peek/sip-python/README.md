# epdg-peek SIP Python scripts

This folder contains helper scripts for SIP testing.

* `run-register-fingerprint.sh`: Script that tests different configurations on a selected P-CSCF server,
    mainly checking the supported `3gpp-ipsec` algorithms.
    This script is often a good entrypoint to check the SIP connectivity.
* `run-register-auth.sh`: Script that tries to perform a registration via `SIP REGISTER`.
    This script requires the SIM card for authentication.
    Depending on the card used, this script might need a few seconds after startup of the IPsec tunnel to work,
    until the strongswan process has released the PC/SC card.
* `burn-phase3.sh`: Cleanup script to remove temporary authentication information and IPsec policies.
    This script can be used to start over with a new registration, or to clean up on a failed registration.
* `start-sip-responder.sh`: Simple SIP UA wrapper script, that answers INVITEs, OPTIONS' and MESSAGEs.
    Mainly useful for connectivity testing, not for a fully correct SIP implementation of edge cases.
* `run-sip-header-testing.sh`: Wrapper script to send simple SIP OPTIONS or INVITE requests with custom headers.
    A set of custom headers is added per default, more headers can be added via the `auth_state.json` file.
