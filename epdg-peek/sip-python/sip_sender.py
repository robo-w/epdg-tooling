#!/usr/bin/env python3

import argparse
import datetime
import os
import re
import secrets
import sys
import socket
import time

from auth_state_util import load_auth_state, save_auth_state
from epdg_definitions import ENV_AUTH_STATE_FILE, ENV_P_CSCF_IP, ENV_OWN_IP, ENV_IMSI, ENV_MCC, ENV_MNC
from sip_utils import SipTarget, create_contact_header, build_sip_target_from_auth_state, send_request, \
    parse_sip_message, FIXED_IMEI

built_invite_lines = None


def build_sip_request(sip_target: SipTarget, args: argparse.Namespace, auth_state: dict) -> bytes:
    global built_invite_lines
    call_id = args.call_id if args.call_id else f"peekaboo_{secrets.token_hex(14)}-{secrets.token_urlsafe(10)}"
    branch = f"z9hG4bK{secrets.token_hex(8)}"
    from_tag = secrets.token_hex(6)

    own_uris = auth_state.get("registration", {}).get("own-uris")
    if own_uris and len(own_uris) > 0:
        local_uri = own_uris[0]
        print(f"Using stored own-URI from auth state: '{local_uri}'", file=sys.stderr)
    else:
        mnc = args.mnc.zfill(3)  # Ensure MNC is 3 digits for realm construction
        realm = f"ims.mnc{mnc}.mcc{args.mcc}.3gppnetwork.org"
        local_uri = f"<sip:{args.imsi}@{realm}>"

    request_uri = f"{args.target}"
    imei = FIXED_IMEI

    own_ip = args.own_ip
    if ":" in own_ip:
        own_ip = f"[{own_ip}]"

    own_contact_uri = f"<sip:{args.imsi}@{own_ip}:{sip_target.own_server_port};transport={sip_target.transport.lower()}>"

    overrides = auth_state.get("overrides", {})
    if overrides:
        for key, value in overrides.items():
            match key:
                case "From":
                    local_uri = value
                case "IMEI":
                    imei = value
                case _:
                    print(f"Unknown override key '{key}' in auth state. Ignoring.", file=sys.stderr)

    method = args.method.upper()
    lines = [
        f"{method} {request_uri} SIP/2.0",
        f"Via: SIP/2.0/{sip_target.transport.upper()} {own_ip}:{sip_target.own_server_port};branch={branch};rport",
        "Max-Forwards: 70",
        "Proxy-Require: sec-agree",
        "Require: sec-agree",
        create_contact_header(own_contact_uri, imei, sms_support=False),
        f"To: <{request_uri}>",
        f"From: {local_uri};tag={from_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {args.cseq} {method}",
        f"Accept: application/sdp, application/3gpp-ims+xml",
        "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, UPDATE, INFO, REFER, NOTIFY, MESSAGE, PRACK",
        # MUST be after the CSeq, for hacky CANCEL creation
        "Supported: 100rel,sec-agree",
        f"User-Agent: PythonSipSender/38.0",
        f"P-Early-Media: supported",
        f"P-Access-Network-Info: IEEE-802.11;i-wlan-node-id={secrets.token_hex(6)}",
        f"Session-ID: {secrets.token_hex(16)}",
        f"X-Fairy-Magic: {secrets.token_hex(7)};{secrets.token_urlsafe(31)};{secrets.token_hex(3)}",
        f"Cellular-Network-Info: 3GPP-GERAN;cgi-3gpp=99999{secrets.token_hex(4)};cell-info-age=42",
    ]

    server_verify_content = auth_state.get("ipsec-server", {}).get("full-content")
    if server_verify_content:
        print("Adding Security-Verify header based on stored IPsec server state.", file=sys.stderr)
        lines.append(f"Security-Verify: {server_verify_content}")
    else:
        print("No IPsec server state found in authentication-state file. Skipping Security-Verify header.",
              file=sys.stderr)

    if args.large_header:
        lines.append(f"X-Advertisement-Content: {secrets.token_urlsafe(200)}")

    additional_headers = auth_state.get("additional-headers", {})
    if additional_headers:
        print(f"Adding {len(additional_headers)} additional headers from auth state.", file=sys.stderr)
        for h, v in additional_headers.items():
            lines.append(f"{h}: {v}")

    lines.append("Content-Length: 0")
    built_invite_lines = lines.copy() if method == "INVITE" else None
    lines.append("")
    lines.append("")

    return "\r\n".join(lines).encode("utf-8")


def build_cancel_request() -> bytes:
    if built_invite_lines is None:
        raise ValueError("Cannot build CANCEL request: no INVITE request has been built yet.")

    cancel_lines = built_invite_lines.copy()
    cancel_lines[0] = cancel_lines[0].replace("INVITE", "CANCEL", 1)
    # find cseq line and increment the sequence number
    for i, line in enumerate(cancel_lines):
        if line.lower().startswith("cseq: "):
            cancel_lines[i] = cancel_lines[i].replace("INVITE", "CANCEL", 1)
            break
    cancel_lines = [line for line in cancel_lines if
                    not line.split(":")[0].lower() in ["content-length", "content-type", "x-unicorn-magic",
                                                       "session-id", "p-access-network-info", "p-early-media", "accept",
                                                       "contact"]]

    cancel_lines.append("Content-Length: 0")
    cancel_lines.append("")
    cancel_lines.append("")

    return "\r\n".join(cancel_lines).encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send a  SIP OPTIONS request.")
    parser.add_argument("--host", default=os.getenv(ENV_P_CSCF_IP), help="P-CSCF host")
    parser.add_argument("--own-ip", default=os.getenv(ENV_OWN_IP), help="own IP address (for Via header)")
    parser.add_argument("--imsi", default=os.getenv(ENV_IMSI), help="IMS Identity (IMSI)")
    parser.add_argument("--mcc", default=os.getenv(ENV_MCC), help="Mobile Country Code")
    parser.add_argument("--mnc", default=os.getenv(ENV_MNC), help="Mobile Network Code")
    parser.add_argument("--transport", default="tcp", choices=["udp", "tcp"], help="SIP transport to use")
    parser.add_argument("--timeout", type=float, default=-1,
                        help="socket timeout in seconds (default: 5 for OPTIONS, 40 for INVITE)")
    parser.add_argument("--call-id", default=None, help="Call-ID to use in SIP request (default: random)")
    parser.add_argument("--cseq", type=int, default=-1,
                        help="CSeq number to use in SIP request")  # TODO: write cseq counter to auth file
    parser.add_argument("--target", required=True, help="Target for SIP OPTIONS request (default: same as host)")
    parser.add_argument("--method", choices=["OPTIONS", "INVITE"], default="OPTIONS",
                        help="SIP method to use (default: OPTIONS)")
    parser.add_argument("--large-header", action="store_true", help="Add a large header to the request")
    parser.add_argument("--expected-responses", type=int, default=-1,
                        help="Number of expected SIP responses (default: 1 for OPTIONS, 3 for INVITE)")
    parser.add_argument("--auth-file", default=os.getenv(ENV_AUTH_STATE_FILE),
                        help="JSON file to read authentication state")

    args = parser.parse_args()
    missing = [name for name in ("host", "imsi", "mcc", "mnc", "own_ip", "auth_file") if not getattr(args, name)]
    if missing:
        parser.error(
            "missing required values for: " + ", ".join(missing) +
            f" (set --host/--imsi/--mcc/--mnc/--own-ip/--auth-file or {ENV_P_CSCF_IP}/{ENV_IMSI}/{ENV_MCC}/{ENV_MNC}/{ENV_OWN_IP}/{ENV_AUTH_STATE_FILE})"
        )

    if not re.match(r"^\d{3}$", args.mcc):
        parser.error(f"invalid MCC: must be 3 digits")

    if not re.match(r"^\d{2,3}$", args.mnc):
        parser.error(f"invalid MNC: must be 2 or 3 digits")

    if not re.match(r"^\d{12,15}$", args.imsi):
        parser.error(f"invalid IMSI: must be 12-15 digits")

    return args


def log_timestamp() -> str:
    return datetime.datetime.now().isoformat(sep=" ", timespec="seconds")


def main() -> int:
    print(f"Starting SIP sender at {log_timestamp()}", file=sys.stderr)
    args = parse_args()
    auth_state = load_auth_state(args.auth_file)

    if auth_state is None:
        print("Auth state is required for server ports!", file=sys.stderr)
        return 5

    cseq = auth_state.get("registration", {}).get("last-cseq", 0)
    if args.cseq == -1:
        args.cseq = cseq + 1
        print(f"Read last CSeq from auth state: {cseq}. Incrementing for new request.", file=sys.stderr)
    else:
        print(f"Using manually provided CSeq {args.cseq}.", file=sys.stderr)

    # TODO: add support for "skip phase 3", by adding default ports here
    target = build_sip_target_from_auth_state(auth_state, args.host, args.transport)
    auth_state["registration"] = auth_state.get("registration", {})
    auth_state["registration"]["last-cseq"] = args.cseq
    save_auth_state(args.auth_file, auth_state)

    request = build_sip_request(target, args, auth_state)

    print(f"\n[>]{log_timestamp()} Created SIP request:", file=sys.stderr)
    print(request.decode("utf-8"), file=sys.stderr)
    print("", file=sys.stderr)

    cancel_timeout = 5
    break_on_final_response = False
    match args.method:
        case "OPTIONS":
            expected_responses = args.expected_responses if args.expected_responses > 0 else 1
            effective_timeout = args.timeout if args.timeout > 0 else 5
        case "INVITE":
            expected_responses = args.expected_responses if args.expected_responses > 0 else 3
            effective_timeout = args.timeout if args.timeout > 0 else 40
            break_on_final_response = True
        case _:
            print(f"[!] Unsupported SIP method: {args.method}", file=sys.stderr)
            return 6

    try:
        response_messages, unparsed_data = send_request(target, request, effective_timeout,
                                                        expected_responses=expected_responses,
                                                        break_on_final_response=break_on_final_response)
    except socket.timeout:
        print("No SIP response received before timeout.", file=sys.stderr)
        print("[!] No SIP response received before timeout.", file=sys.stderr)
        return 1
    except ConnectionRefusedError:
        print("[!] Connection refused by the target.", file=sys.stderr)
        return 2

    if len(response_messages) > 0:

        received_status_lines = []
        valid_responses = 0
        for i, response_bytes in enumerate(response_messages):
            response_str = response_bytes.decode("utf-8", errors="replace")
            received_status_lines.append(response_str.splitlines()[0])
            print(response_str)
            if response_str.strip().startswith("SIP/2.0 "):
                print(f"[<] {log_timestamp()} Got SIP response {i + 1}/{len(response_messages)}:", file=sys.stderr)
                print(response_str, file=sys.stderr)
                valid_responses += 1
            else:
                print(f"[!] Received does not look like a valid SIP response. length: {len(response_str)}",
                      file=sys.stderr)

        status_codes = [int(line.split()[1]) for line in received_status_lines if len(line.split()) > 1]
        if args.method == "INVITE":
            if any(code >= 300 for code in status_codes):
                print(f"[!] Received error response for INVITE. Skipping CANCEL. Status codes: {status_codes}",
                      file=sys.stderr)
            elif any(code >= 200 for code in status_codes):
                print(f"[!] Remote party unexpectedly accepted the call..? Status codes: {status_codes}",
                      file=sys.stderr)
                # TODO: Be nice and send a BYE
                # For now, the missing ACK will terminate the call with a timeout
            else:
                print(f"[i] Got provisional response(s) for INVITE. Sending CANCEL. Status codes: {status_codes}",
                      file=sys.stderr)
                cancel_request = build_cancel_request()
                print("\n[>] Created CANCEL request:", file=sys.stderr)
                print(cancel_request.decode("utf-8"), file=sys.stderr)
                print("", file=sys.stderr)
                try:
                    response_messages, unparsed_data = send_request(target, cancel_request, cancel_timeout,
                                                                    expected_responses=1)
                except OSError as e:
                    if e.errno == 99:
                        # Our source port is still blocked, let's wait a second
                        time.sleep(1.5)
                        response_messages, unparsed_data = send_request(target, cancel_request, cancel_timeout,
                                                                        expected_responses=1)
                    else:
                        raise

                if len(response_messages) > 0:
                    cancel_response_str = response_messages[0].decode("utf-8", errors="replace")
                    if cancel_response_str.strip().startswith("SIP/2.0 "):
                        for i, message in enumerate(response_messages):
                            print(f"[<] {log_timestamp()} Got CANCEL response {i + 1}/{len(response_messages)}:",
                                  file=sys.stderr)
                            print(message.decode("utf-8", errors="replace"), file=sys.stderr)
                            print("")
                            valid_responses += 1
                    else:
                        print(
                            f"{log_timestamp()} Received does not look like a valid SIP response to CANCEL. length: {len(cancel_response_str)}",
                            file=sys.stderr)

        return 0 if valid_responses > 0 else 3
    else:
        print("No SIP response received.", file=sys.stderr)
        if unparsed_data:
            print(f"Unparsed data length: {len(unparsed_data)}", file=sys.stderr)
            print(f"Unparsed data (hex, up to 200 bytes): {unparsed_data[:200].hex()}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
