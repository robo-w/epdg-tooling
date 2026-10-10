#!/usr/bin/env python3

import argparse
import base64
import os
import re
import secrets
import socket
import sys
from auth_akav1 import calculate_aka_digest
from auth_state_util import load_auth_state, save_auth_state
from epdg_definitions import ENV_P_CSCF_IP, ENV_OWN_IP, ENV_IMSI, ENV_MCC, ENV_MNC
from sip_utils import SipTarget, build_sip_target_from_auth_state, get_sip_header, send_request, FIXED_IMEI

A_SHA1 = "hmac-sha-1-96"  # Supported
A_MD5 = "hmac-md5-96"  # Removed => insecure
A_NULL = "null"  # Only allowed with 'ealg=aes-gcm'

E_AES = "aes-cbc"  # Supported
E_AES_GCM = "aes-gcm"  # Supported
E_DES = "des-ede3-cbc"  # Removed => insecure
E_NULL = "null"  # Supported, treated as insecure

CLIENT_PORT_C = 9804
CLIENT_PORT_S = 9800

CIPHER_PROFILES = ["default", "f11-encr-null", "aes-cbc", "f11-encr-des", "f11-auth-md5", "f11-invalid-auth-null",
                   "f11-aead-auth-null", "suppress-header"]


def build_proposals(cipher: str, auth_state: dict | None = None) -> tuple[str, str]:
    if auth_state is not None:
        spi_c = auth_state.get("ipsec-client", {}).get("spi-c")
        spi_s = auth_state.get("ipsec-client", {}).get("spi-s")
        if spi_c is not None and spi_s is not None:
            print(f"Using stored SPI values from auth state: spi-c={spi_c}, spi-s={spi_s}", file=sys.stderr)
        else:
            spi_c = secrets.randbelow(20000)
            spi_s = spi_c + 1
            print(f"No stored SPI values found in auth state. Generated new SPIs: spi-c={spi_c}, spi-s={spi_s}",
                  file=sys.stderr)
    else:
        spi_c = secrets.randbelow(20000)
        spi_s = spi_c + 1
        print(f"No auth file provided. Generated new SPIs: spi-c={spi_c}, spi-s={spi_s}", file=sys.stderr)

    proposal_template = f"ipsec-3gpp;prot=esp;mod=trans;spi-c={spi_c};spi-s={spi_s};port-c={CLIENT_PORT_C};port-s={CLIENT_PORT_S};alg=%s;ealg=%s"
    if auth_state is not None:
        auth_state["ipsec-client"] = {"spi-c": spi_c, "spi-s": spi_s, "port-c": CLIENT_PORT_C, "port-s": CLIENT_PORT_S}

    proposals = ""
    if cipher == "default":
        proposals = f"{proposal_template % (A_MD5, E_AES)}, {proposal_template % (A_MD5, E_NULL)}, {proposal_template % (A_SHA1, E_AES)}, {proposal_template % (A_SHA1, E_NULL)}"
    elif cipher == "f11-encr-null":
        proposals = f"{proposal_template % (A_MD5, E_NULL)}, {proposal_template % (A_SHA1, E_NULL)}"
    elif cipher == "f11-encr-des":
        proposals = f"{proposal_template % (A_MD5, E_DES)}, {proposal_template % (A_SHA1, E_DES)}"
    elif cipher == "f11-auth-md5":
        proposals = f"{proposal_template % (A_MD5, E_NULL)}, {proposal_template % (A_MD5, E_AES)}"
    elif cipher == "f11-invalid-auth-null":
        proposals = f"{proposal_template % (A_NULL, E_NULL)}, {proposal_template % (A_NULL, E_AES)}"
    elif cipher == "f11-aead-auth-null":
        proposals = f"{proposal_template % (A_NULL, E_AES_GCM)}"
    elif cipher == "aes-cbc":
        proposals = f"{proposal_template % (A_MD5, E_AES)}, {proposal_template % (A_SHA1, E_AES)}"
    elif cipher == "suppress-header":
        pass
    else:
        raise ValueError(f"Invalid cipher option: {cipher}")

    user_agent_suffix = ""
    if cipher != "default":
        user_agent_suffix = " CipherEnumerationForSecurityResearch/1.0"

    return proposals, user_agent_suffix


def get_expires_value(sip_expires: str) -> int:
    match sip_expires:
        case "too-little":
            expires_value = 600
        case "minimum":
            expires_value = 3600
        case "day":
            expires_value = 86400
        case "year":
            expires_value = 31536000
        case "eternity":
            expires_value = 2147483647
        case _:
            raise ValueError(f"Invalid SIP Expires option: {sip_expires}")

    return expires_value


def build_register_request(target: SipTarget, args: argparse.Namespace, auth_state: dict | None = None) -> bytes:
    mnc = args.mnc.zfill(3)  # Ensure MNC is 3 digits for realm construction
    call_id = args.call_id if args.call_id else f"{secrets.token_hex(14)}"
    branch = f"z9hG4bK{secrets.token_hex(8)}"
    from_tag = secrets.token_hex(6)
    realm = f"ims.mnc{mnc}.mcc{args.mcc}.3gppnetwork.org"
    local_uri = f"sip:{args.imsi}@{realm}"
    request_uri = f"sip:{realm}"
    imei = FIXED_IMEI

    proposals, user_agent_suffix = build_proposals(args.cipher, auth_state)
    expires_value = get_expires_value(args.sip_expires)

    own_ip = args.own_ip
    if ":" in own_ip:
        own_ip = f"[{own_ip}]"

    lines = [
        f"REGISTER {request_uri} SIP/2.0",
        f"Via: SIP/2.0/{target.transport.upper()} {own_ip}:{target.own_server_port};branch={branch};rport",
        "Max-Forwards: 70",
        f"Contact: <sip:{args.imsi}@{own_ip}:{target.own_server_port};transport={target.transport.lower()}>;+sip.instance=\"<urn:gsma:imei:{imei}>\";q=1.0;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";+g.3gpp.smsip",
        f"To: <{local_uri}>",
        f"From: <{local_uri}>;tag={from_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {args.cseq} REGISTER",
        f"Expires: {expires_value}",
        "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, UPDATE, INFO, REFER, NOTIFY, MESSAGE, PRACK",
        "Supported: sec-agree",
        f"User-Agent: PythonSipRegister/42.0{user_agent_suffix}",
        f"P-Access-Network-Info: IEEE-802.11;i-wlan-node-id={secrets.token_hex(6)}",
        # f"Cellular-Network-Info: 3GPP-GERAN;cgi-3gpp={mcc}{mnc}{secrets.token_hex(6)};cell-info-age=42",
    ]

    if args.cipher == "suppress-header":
        print("Suppressing Security-Client header.", file=sys.stderr)
    else:
        lines.append("Proxy-Require: sec-agree")
        lines.append("Require: sec-agree")
        print(f"Using preset '{args.cipher}' for Security-Client header.", file=sys.stderr)
        lines.append(f"Security-Client: {proposals}")

    auth_username = f"{args.imsi}@{realm}"
    if auth_state is None:
        # TODO: As an additional test, this header can be left out as well. Currently not configurable.
        lines.append(
            f"Authorization: Digest username=\"{auth_username}\",realm=\"{realm}\",uri=\"{request_uri}\",nonce=\"\",response=\"\",algorithm=AKAv1-MD5")
    else:
        nonce = auth_state.get("challenge", {}).get("nonce")
        sim_res = auth_state.get("challenge", {}).get("res")
        auts = auth_state.get("challenge", {}).get("auts")
        opaque = auth_state.get("challenge", {}).get("opaque")

        if nonce and sim_res:
            response = calculate_aka_digest(auth_username, realm, sim_res, nonce, request_uri)
            print(f"Trying to authorize for nonce='{nonce}' with response='{response}', hashed from", file=sys.stderr)
            print(f"  username='{auth_username}', realm='{realm}', sim_res='{sim_res}'", file=sys.stderr)
            # print(f"  request_uri='{request_uri}', ha1='{ha1}', ha2='{ha2}', aka_password.hex='{aka_password.hex()}'", file=sys.stderr)
            authorization_line = f"Authorization: Digest username=\"{auth_username}\",realm=\"{realm}\",uri=\"{request_uri}\",nonce=\"{nonce}\",response=\"{response}\",algorithm=AKAv1-MD5"
            if opaque:
                authorization_line += f",opaque=\"{opaque}\""
            lines.append(authorization_line)

            server_verify_content = auth_state.get("ipsec-server", {}).get("full-content")
            if server_verify_content:
                print("Adding Security-Verify header based on stored IPsec server state.", file=sys.stderr)
                lines.append(f"Security-Verify: {server_verify_content}")
            else:
                print(
                    "No complete IPsec server state found in authentication-state file. Skipping Security-Verify header.",
                    file=sys.stderr)
        elif nonce and auts:
            del auth_state["challenge"]["auts"]
            response = calculate_aka_digest(auth_username, realm, None, nonce, request_uri)
            auts_b64 = base64.b64encode(bytes.fromhex(auts)).decode("ascii")
            print(
                f"Trying to authorize for nonce='{nonce}' with AUTS='{auts}' ({auts_b64}) and response='{response}' (resync request)",
                file=sys.stderr)
            lines.append(
                f"Authorization: Digest username=\"{auth_username}\",realm=\"{realm}\",uri=\"{request_uri}\",nonce=\"{nonce}\",response=\"{response}\",auts=\"{auts_b64}\",algorithm=AKAv1-MD5")
        else:
            # Samsung sends an authorization header with empty values in the first request, but per RFC it is not required.
            lines.append(
                f"Authorization: Digest username=\"{auth_username}\",realm=\"{realm}\",uri=\"{request_uri}\",nonce=\"\",response=\"\",algorithm=AKAv1-MD5")
            # print("No nonce/response present in authentication-state file. Skipping Authorization header.", file=sys.stderr)

    lines.append("Content-Length: 0")
    lines.append("")
    lines.append("")

    return "\r\n".join(lines).encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send an initial SIP REGISTER request.")
    parser.add_argument("--host", default=os.getenv(ENV_P_CSCF_IP), help="P-CSCF host")
    parser.add_argument("--own-ip", default=os.getenv(ENV_OWN_IP), help="own IP address (for Via header)")
    parser.add_argument("--port", type=int, default=5060,
                        help="SIP port on server to use. Ignored when auth_state present.")
    parser.add_argument("--imsi", default=os.getenv(ENV_IMSI), help="IMS Identity (IMSI)")
    parser.add_argument("--mcc", default=os.getenv(ENV_MCC), help="Mobile Country Code")
    parser.add_argument("--mnc", default=os.getenv(ENV_MNC), help="Mobile Network Code")
    parser.add_argument("--transport", default="tcp", choices=["udp", "tcp"], help="SIP transport to use")
    parser.add_argument("--timeout", type=float, default=4.0, help="socket timeout in seconds")
    parser.add_argument("--cipher", default="default", choices=CIPHER_PROFILES,
                        help="Profile to test the ealg and alg parameters in the Security-Client header")
    parser.add_argument("--sip-expires", default="minimum",
                        choices=["too-little", "minimum", "day", "year", "eternity"],
                        help="Value to use in SIP Expires header")
    parser.add_argument("--call-id", default=None, help="Call-ID to use in SIP request (default: random)")
    parser.add_argument("--cseq", type=int, default=-1, help="CSeq number to use in SIP request")
    parser.add_argument("--auth-file", default=None, help="JSON file to read and store authentication state")

    args = parser.parse_args()
    missing = [name for name in ("host", "imsi", "mcc", "mnc", "own_ip") if not getattr(args, name)]
    if missing:
        parser.error(
            "missing required values for: " + ", ".join(missing) +
            f" (set --host/--imsi/--mcc/--mnc/--own-ip or {ENV_P_CSCF_IP}/{ENV_IMSI}/{ENV_MCC}/{ENV_MNC}/{ENV_OWN_IP})"
        )

    if not re.match(r"^\d{3}$", args.mcc):
        parser.error(f"invalid MCC: must be 3 digits")

    if not re.match(r"^\d{2,3}$", args.mnc):
        parser.error(f"invalid MNC: must be 2 or 3 digits")

    if not re.match(r"^\d{12,15}$", args.imsi):
        parser.error(f"invalid IMSI: must be 12-15 digits")

    return args


def handle_sip_response(response_str: str, auth_state: dict, auth_file: str) -> None:
    auth_header = get_sip_header(response_str, "WWW-Authenticate")
    if auth_header:
        print("Received WWW-Authenticate header. Updating auth state.", file=sys.stderr)
        nonce_match = re.search(r'nonce="([^"]+)"', auth_header)
        opaque_match = re.search(r'opaque="([^"]+)"', auth_header)
        if auth_state.get("challenge") is None:
            auth_state["challenge"] = {}
        if nonce_match:
            auth_state["challenge"]["nonce"] = nonce_match.group(1)
        if opaque_match:
            auth_state["challenge"]["opaque"] = opaque_match.group(1)

    security_server_header = get_sip_header(response_str, "Security-Server")
    if security_server_header:
        print("Received Security-Server header. Updating auth state.", file=sys.stderr)
        # Example: Security-Server: ipsec-3gpp;prot=esp;mod=trans;spi-c=1234;spi-s=1235;port-c=9800;port-s=9900;alg=hmac-sha-1-96;ealg=aes-cbc
        spi_c_match = re.search(r'spi-c[ ]?=[ ]?(\d+)', security_server_header)
        spi_s_match = re.search(r'spi-s[ ]?=[ ]?(\d+)', security_server_header)
        port_c_match = re.search(r'port-c[ ]?=[ ]?(\d+)', security_server_header)
        port_s_match = re.search(r'port-s[ ]?=[ ]?(\d+)', security_server_header)
        alg_match = re.search(r';[ ]?alg[ ]?=[ ]?([a-zA-Z0-9-]+)', security_server_header)
        ealg_match = re.search(r';[ ]?ealg[ ]?=[ ]?([a-zA-Z0-9-]+)', security_server_header)
        qop_match = re.search(r'qop[ ]?=[ ]?"([a-zA-Z]+)"', security_server_header)
        if spi_c_match and spi_s_match and port_c_match and port_s_match and alg_match and ealg_match:
            auth_state["ipsec-server"] = {
                "spi-c": int(spi_c_match.group(1)),
                "spi-s": int(spi_s_match.group(1)),
                "port-c": int(port_c_match.group(1)),
                "port-s": int(port_s_match.group(1)),
                "alg": alg_match.group(1),
                "ealg": ealg_match.group(1),
                "full-content": security_server_header
            }
            if qop_match:
                auth_state["ipsec-server"]["qop"] = qop_match.group(1)
        else:
            print("No Security-Server header to parse.", file=sys.stderr)

    auth_state["registration"] = auth_state.get("registration", {})
    p_associated_uri_header = get_sip_header(response_str, "P-Associated-URI")
    if p_associated_uri_header:
        print("Received P-Associated-URI header. Updating auth state.", file=sys.stderr)
        own_uris = p_associated_uri_header.split(",")
        auth_state["registration"]["own-uris"] = [uri.strip() for uri in own_uris]

    service_route_header = get_sip_header(response_str, "Service-Route")
    if service_route_header:
        print("Received Service-Route header. Updating auth state.", file=sys.stderr)
        service_routes = service_route_header.split(",")
        auth_state["registration"]["service-routes"] = [route.strip() for route in service_routes]

    auth_state["registration"]["last-cseq"] = auth_state.get("registration", {}).get("last-cseq", 0) + 1

    save_auth_state(auth_file, auth_state)


def main() -> int:
    args = parse_args()
    auth_state = load_auth_state(args.auth_file)

    # Use client_port=0 to let OS chose the source port => reduces conflicts on re-using it.
    # Fixed source port is only mandatory, as soon as IPsec transport mode is active; when loaded from auth_state.
    target = SipTarget(host=args.host, server_port=args.port, client_port=0, own_server_port=5060,
                       transport=args.transport)
    if auth_state is not None:
        try:
            target = build_sip_target_from_auth_state(auth_state, args.host, args.transport)
        except ValueError:
            print("No server/client port information found in auth state. Using default ports.", file=sys.stderr)

        cseq = auth_state.get("registration", {}).get("last-cseq", 0)
        if args.cseq == -1:
            print(f"Using last CSeq from auth state: {cseq}. Incrementing for new request.", file=sys.stderr)
            args.cseq = cseq + 1

    if args.cseq == -1:
        print("No CSeq provided and no auth state found. Using default CSeq=1.", file=sys.stderr)
        args.cseq = 1

    request = build_register_request(target, args, auth_state)

    print("\nCreated SIP request:", file=sys.stderr)
    print(request.decode("utf-8"), file=sys.stderr)
    print("", file=sys.stderr)

    try:
        response_messages, unparsed_data = send_request(target, request, args.timeout)
    except socket.timeout:
        print("No SIP response received before timeout.", file=sys.stderr)
        return 1
    except ConnectionRefusedError:
        print("Connection refused by the target.", file=sys.stderr)
        return 2

    if len(response_messages) > 0:
        response_str = response_messages[0].decode("utf-8", errors="replace")
        print(response_str)
        if response_str.strip().startswith("SIP/2.0 "):
            print("Got a SIP response.", file=sys.stderr)
            print(response_str, file=sys.stderr)

            if auth_state is not None and args.auth_file is not None:
                handle_sip_response(response_str, auth_state, args.auth_file)

            return 0
        else:
            print(f"Received does not look like a valid SIP response. length: {len(response_str)}", file=sys.stderr)
            return 3
    else:
        print("No SIP response received.", file=sys.stderr)
        if unparsed_data:
            print(f"Unparsed data length: {len(unparsed_data)}", file=sys.stderr)
            print(f"Unparsed data (hex, up to 200 bytes): {unparsed_data[:200].hex()}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
