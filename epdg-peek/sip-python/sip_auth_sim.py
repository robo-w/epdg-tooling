#!/usr/bin/env python3

# Adapted
# based on 'ami_usim.py'
#   from https://osmocom.org/projects/foss-ims-client/wiki/VoWiFi_with_Asterisk
#   2025, CC-BY-SA-3.0 "jolly", Andreas Eversberg
# by
#   2026, CC-BY-SA-3.0 "robo-w", Robert Wittek

# 'smartcard' is provided by pyscard, not any other package!
import argparse
import base64
import os
import subprocess
import sys

from auth_state_util import load_auth_state, save_auth_state
from smartcard.System import readers
from smartcard.util import toHexString, toBytes


# Do USIM authentication, return RES/CK/IK vector || AUTS || None
def read_res_ck_ik(reader_index: int, rand: str, autn: str) -> tuple[str | None, str | None, str | None, str | None]:
    res = None
    ck = None
    ik = None
    auts = None
    r = readers()
    connection = r[int(reader_index)].createConnection()
    connection.connect()

    # Select EF.DIR
    data, sw1, sw2 = connection.transmit(toBytes('00a40004022f0000'))
    if sw1 != 97:
        print("  *** ERROR *** Failed to select EF.DIR", file=sys.stderr)
        return res, ck, ik, auts
    data, sw1, sw2 = connection.transmit(toBytes('00C00000') + [sw2])
    result = toHexString(data).replace(" ", "")
    record_length = data[7]
    # Read first AID
    data, sw1, sw2 = connection.transmit(toBytes('00b20104') + [record_length])
    if sw1 != 144:
        print("  *** ERROR *** Failed to get AID", file=sys.stderr)
        return res, ck, ik, auts
    result = toHexString(data).replace(" ", "")
    aid_length = data[3]
    aid = result[8:(8 + aid_length * 2)]
    print(f"  Using aid={aid}", file=sys.stderr)

    # Select AID
    data, sw1, sw2 = connection.transmit(toBytes('00a40404') + [aid_length] + toBytes(aid))
    if sw1 != 97:
        print("  *** ERROR *** Failed to select AID", file=sys.stderr)
        return res, ck, ik, auts
    # Authenticate
    data, sw1, sw2 = connection.transmit(toBytes('008800812210' + rand.upper() + '10' + autn.upper()))
    if sw1 == 97:
        data, sw1, sw2 = connection.transmit(toBytes('00C00000') + [sw2])
        result = toHexString(data).replace(" ", "")
        print(f"  Authentication result='{result}'", file=sys.stderr)
        rc = result[0:2]
        if rc == 'DB':
            res_length = data[1]
            res = result[4:(4 + res_length * 2)]
            ck_length = data[2 + res_length]
            ck = result[(6 + res_length * 2):(6 + res_length * 2 + ck_length * 2)]
            ik_length = data[2 + res_length + 1 + ck_length]
            ik = result[(8 + res_length * 2 + ck_length * 2):(8 + res_length * 2 + ck_length * 2 + ik_length * 2)]
        elif rc == 'DC':
            auts = result[4:32]
    else:
        print(f"  *** ERROR *** Authentication failed.", file=sys.stderr)

    return res, ck, ik, auts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Perform SIM authentication and bootstrap IPsec transport mode.")
    parser.add_argument("--host", default=os.getenv("IMS_PCSCF_IP"), help="P-CSCF host")
    parser.add_argument("--own-ip", default=os.getenv("IPSEC_LOCAL_IP"), help="own IP address (for IPsec policy)")
    parser.add_argument("--auth-file", help="JSON file to read and store authentication state")
    parser.add_argument("--skip-ipsec", action="store_true",
                        help="Skip IPsec configuration (only perform SIM authentication)")

    args = parser.parse_args()
    missing = [name for name in ("host", "auth_file", "own_ip") if not getattr(args, name)]
    if missing:
        parser.error(
            "missing required values for: " + ", ".join(missing) +
            " (set --host/--auth-file/--own-ip or IMS_PCSCF_IP/IPSEC_LOCAL_IP)"
        )

    return args


def main() -> int:
    args = parse_args()
    auth_state = load_auth_state(args.auth_file)
    if auth_state is None:
        print("No auth state file provided, exiting.", file=sys.stderr)
        return 1

    nonce = auth_state.get("challenge", {}).get("nonce")
    if nonce is None:
        print("No nonce found in auth state, exiting.", file=sys.stderr)
        return 1

    if os.geteuid() != 0:
        print("This script must be run as root to configure IPsec policies.", file=sys.stderr)
        return 1

    nonce_bytes = base64.b64decode(nonce)
    rand = nonce_bytes[:16].hex()
    autn = nonce_bytes[16:32].hex()

    print(f"Using rand='{rand}' autn='{autn}' from nonce='{nonce}' for SIM authentication", file=sys.stderr)
    res, ck, ik, auts = read_res_ck_ik(0, rand, autn)

    if auts is not None:
        print(f"Got AUTS='{auts}' from SIM.", file=sys.stderr)
        auth_state["challenge"]["auts"] = auts.lower()
        save_auth_state(args.auth_file, auth_state)
        return 20

    if res is not None and ck is not None and ik is not None:
        auth_state["challenge"]["res"] = res.lower()
        auth_state["challenge"]["ck"] = ck.lower()
        auth_state["challenge"]["ik"] = ik.lower()
        save_auth_state(args.auth_file, auth_state)
        print(f"Authentication state successfully updated. RES='{res}' CK='{ck}' IK='{ik}'", file=sys.stderr)
    else:
        print("Failed to get RES/CK/IK from SIM.", file=sys.stderr)
        return 2

    if args.skip_ipsec:
        print("Skipping IPsec configuration as requested.", file=sys.stderr)
        return 0

    pcscf_ip = args.host
    own_ip = args.own_ip
    if pcscf_ip is None or own_ip is None:
        print("P-CSCF IP or own IP not provided, IPsec policy cannot be configured.", file=sys.stderr)
        return 3

    ip_family = "ipv6" if ":" in own_ip else "ipv4"
    if ip_family == "ipv4" and ":" in pcscf_ip:
        print("Own IP is IPv4 but P-CSCF IP is IPv6, cannot configure IPsec policy.", file=sys.stderr)
        return 3
    if ip_family == "ipv6" and ":" not in pcscf_ip:
        print("Own IP is IPv6 but P-CSCF IP is IPv4, cannot configure IPsec policy.", file=sys.stderr)
        return 3

    server_spi_c = auth_state.get("ipsec-server", {}).get("spi-c")
    server_spi_s = auth_state.get("ipsec-server", {}).get("spi-s")
    server_port_c = auth_state.get("ipsec-server", {}).get("port-c")
    server_port_s = auth_state.get("ipsec-server", {}).get("port-s")
    if server_spi_c is None or server_spi_s is None or server_port_c is None or server_port_s is None:
        print("IPsec server properties not found in auth state, cannot configure IPsec policy.", file=sys.stderr)
        return 3

    ipsec_alg = auth_state.get("ipsec-server", {}).get("alg")
    ipsec_ealg = auth_state.get("ipsec-server", {}).get("ealg")
    if ipsec_alg is None or ipsec_ealg is None:
        print("IPsec algorithms not found in auth state, cannot configure IPsec policy.", file=sys.stderr)
        return 3

    client_spi_c = auth_state.get("ipsec-client", {}).get("spi-c")
    client_spi_s = auth_state.get("ipsec-client", {}).get("spi-s")
    client_port_c = auth_state.get("ipsec-client", {}).get("port-c")
    client_port_s = auth_state.get("ipsec-client", {}).get("port-s")
    if client_spi_c is None or client_spi_s is None or client_port_c is None or client_port_s is None:
        print("IPsec client properties not found in auth state, cannot configure IPsec policy.", file=sys.stderr)
        return 3

    server_spi_c_hex = f"0x{server_spi_c:08x}"
    server_spi_s_hex = f"0x{server_spi_s:08x}"
    client_spi_c_hex = f"0x{client_spi_c:08x}"
    client_spi_s_hex = f"0x{client_spi_s:08x}"

    print("Configuring IPsec policy:", file=sys.stderr)
    print(f"  P-CSCF IP: {pcscf_ip}", file=sys.stderr)
    print(f"  Own IP: {own_ip}", file=sys.stderr)
    print(f"  Server SPI-C: {server_spi_c} ({server_spi_c_hex})", file=sys.stderr)
    print(f"  Server SPI-S: {server_spi_s} ({server_spi_s_hex})", file=sys.stderr)
    print(f"  Client SPI-C: {client_spi_c} ({client_spi_c_hex})", file=sys.stderr)
    print(f"  Client SPI-S: {client_spi_s} ({client_spi_s_hex})", file=sys.stderr)
    print(f"  Server Port-C: {server_port_c}", file=sys.stderr)
    print(f"  Server Port-S: {server_port_s}", file=sys.stderr)
    print(f"  Client Port-C: {client_port_c}", file=sys.stderr)
    print(f"  Client Port-S: {client_port_s}", file=sys.stderr)

    if ipsec_alg == "hmac-sha-1-96":
        xfrm_auth_key = "0x" + ik.lower() + "00000000"
        xfrm_auth_type = "hmac(sha1)"
    elif ipsec_alg == "hmac-md5-96":
        xfrm_auth_key = "0x" + ik.lower()
        xfrm_auth_type = "hmac(md5)"
    else:
        print(f"Unsupported IPsec authentication algorithm '{ipsec_alg}'", file=sys.stderr)
        return 3

    if ipsec_ealg == "aes-cbc":
        xfrm_enc_key = "0x" + ck.lower()
        xfrm_enc_type = "cbc(aes)"
    elif ipsec_ealg == "null":
        xfrm_enc_key = ""
        xfrm_enc_type = "ecb(cipher_null)"
    else:
        print(f"Unsupported IPsec encryption algorithm '{ipsec_ealg}'", file=sys.stderr)
        return 3

    cmd_state_out_server_c = [
        "ip", "netns", "exec", "ims",
        "ip", "xfrm", "state", "add",
        "src", own_ip, "dst", pcscf_ip,
        "proto", "esp", "spi", server_spi_c_hex,
        "reqid", "41", "mode", "transport",
        "auth-trunc", xfrm_auth_type, xfrm_auth_key, "96",
        "enc", xfrm_enc_type, xfrm_enc_key]
    cmd_state_out_server_s = [
        "ip", "netns", "exec", "ims",
        "ip", "xfrm", "state", "add",
        "src", own_ip, "dst", pcscf_ip,
        "proto", "esp", "spi", server_spi_s_hex,
        "reqid", "42", "mode", "transport",
        "auth-trunc", xfrm_auth_type, xfrm_auth_key, "96",
        "enc", xfrm_enc_type, xfrm_enc_key]
    cmd_state_in_client_c = [
        "ip", "netns", "exec", "ims",
        "ip", "xfrm", "state", "add",
        "src", pcscf_ip, "dst", own_ip,
        "proto", "esp", "spi", client_spi_c_hex,
        "reqid", "43", "mode", "transport",
        "auth-trunc", xfrm_auth_type, xfrm_auth_key, "96",
        "enc", xfrm_enc_type, xfrm_enc_key]
    cmd_state_in_client_s = [
        "ip", "netns", "exec", "ims",
        "ip", "xfrm", "state", "add",
        "src", pcscf_ip, "dst", own_ip,
        "proto", "esp", "spi", client_spi_s_hex,
        "reqid", "44", "mode", "transport",
        "auth-trunc", xfrm_auth_type, xfrm_auth_key, "96",
        "enc", xfrm_enc_type, xfrm_enc_key]

    print("Installing IPsec xfrm states...", file=sys.stderr)
    for cmd in [cmd_state_out_server_c, cmd_state_out_server_s, cmd_state_in_client_c, cmd_state_in_client_s]:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to execute ip xfrm state command: {e}", file=sys.stderr)
            return 4

    any_ip_str = "::" if ip_family == "ipv6" else "0.0.0.0"

    cmd_policy_out_server_c = [
        "ip", "netns", "exec", "ims",
        "ip", "xfrm", "policy", "add",
        "src", own_ip, "dst", pcscf_ip,
        "sport", str(client_port_s), "dport", str(server_port_c),
        "dir", "out", "priority", "0",
        "tmpl", "src", any_ip_str, "dst", any_ip_str,
        "proto", "esp", "reqid", "41", "mode", "transport"]
    cmd_policy_out_server_s = [
        "ip", "netns", "exec", "ims",
        "ip", "xfrm", "policy", "add",
        "src", own_ip, "dst", pcscf_ip,
        "sport", str(client_port_c), "dport", str(server_port_s),
        "dir", "out", "priority", "0",
        "tmpl", "src", any_ip_str, "dst", any_ip_str,
        "proto", "esp", "reqid", "42", "mode", "transport"]
    cmd_policy_in_client_c = [
        "ip", "netns", "exec", "ims",
        "ip", "xfrm", "policy", "add",
        "src", pcscf_ip, "dst", own_ip,
        "sport", str(server_port_s), "dport", str(client_port_c),
        "dir", "in", "priority", "0",
        "tmpl", "src", any_ip_str, "dst", any_ip_str,
        "proto", "esp", "reqid", "43", "mode", "transport"]
    cmd_policy_in_client_s = [
        "ip", "netns", "exec", "ims",
        "ip", "xfrm", "policy", "add",
        "src", pcscf_ip, "dst", own_ip,
        "sport", str(server_port_c), "dport", str(client_port_s),
        "dir", "in", "priority", "0",
        "tmpl", "src", any_ip_str, "dst", any_ip_str,
        "proto", "esp", "reqid", "44", "mode", "transport"]

    print("Installing IPsec xfrm policies...", file=sys.stderr)
    for cmd in [cmd_policy_out_server_c, cmd_policy_out_server_s, cmd_policy_in_client_c, cmd_policy_in_client_s]:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to execute ip xfrm policy command: {e}", file=sys.stderr)
            return 4

    print("IPsec transport mode successfully configured.", file=sys.stderr)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
