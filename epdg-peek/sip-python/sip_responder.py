#!/usr/bin/env python3
"""
Minimal SIP server over TCP.

Listens on a given TCP port, accepts SIP requests, and replies to
OPTIONS, INVITE, and MESSAGE with basic 200 OK responses.

Usage:
    python3 sip_server.py [port] [--host HOST]

Example:
    python3 sip_server.py 5060
"""

import argparse
import datetime
import os
import secrets
import socket
import sys
import threading

from auth_state_util import load_auth_state
from epdg_definitions import ENV_AUTH_STATE_FILE, ENV_OWN_IP, ENV_P_CSCF_IP
from sip_utils import SipStreamParser, parse_sip_message, create_reuse_connection
from time import sleep

SERVER_NAME_TEMPLATE = "ChattyCuckoo/5.1 (%s)"
USER_AGENT_TEMPLATE = "ChattyCuckoo/9.3 (%s)"


def build_response(status_code: int, reason: str, received_headers: dict, body: str = "",
                   add_to_tag_if_absent: str | None = None, additional_headers: dict = {}) -> str:
    """Build a SIP response reusing key headers from the request."""
    resp_lines = [f"SIP/2.0 {status_code} {reason}"]

    # Headers that must be copied back verbatim (per RFC 3261)
    for h in ("via", "from", "to", "call-id", "cseq"):
        if h in received_headers:
            resp_lines.append(f"{h.title()}: {received_headers[h]}")
            if h == "to" and add_to_tag_if_absent and "tag=" not in received_headers[h]:
                resp_lines[-1] += ";tag=" + add_to_tag_if_absent

    resp_lines.append(f"Server: {SERVER_NAME_TEMPLATE % secrets.token_hex(3)}")
    resp_lines.append(f"User-Agent: {USER_AGENT_TEMPLATE % secrets.token_hex(3)}")
    resp_lines.append(
        f"X-Nothing-To-See-Here: \"Cuckoos LOVE to eat SIP headers, but sometimes they spit them out again\";{secrets.token_hex(17)}")
    resp_lines.append(f"Cellular-Network-Info: 3GPP-GERAN;cgi-3gpp=99999{secrets.token_hex(4)};cell-info-age=58")
    if additional_headers:
        for h, v in additional_headers.items():
            resp_lines.append(f"{h.title()}: {v}")

    resp_lines.append("Content-Length: %d" % len(body))
    if body:
        resp_lines.append("Content-Type: application/sdp")
    resp_lines.append("")
    resp_lines.append(body)  # Either body, or the second line break

    return "\r\n".join(resp_lines)


def handle_options(received_headers) -> str:
    # Advertise what we support; no body needed
    additional_headers = {
        "Allow": "INVITE, ACK, CANCEL, OPTIONS, BYE, MESSAGE",
        "Accept": "application/sdp"
    }
    return build_response(200, "OK", received_headers, additional_headers=additional_headers)


def handle_invite(received_headers, own_ip) -> list[str]:
    # Minimal SDP answer so a peer doing a basic call test gets something back
    local_ip = own_ip
    to_tag = secrets.token_hex(14)
    sdp = (
        f"v=0\r\n"
        f"o=- 0 0 IN IP4 {local_ip}\r\n"
        f"s=SimplePySIP\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        f"t=0 0\r\n"
        f"m=audio 0 RTP/AVP 0\r\n"
        f"a=rtpmap:0 PCMU/8000\r\n"
    )
    # return build_response(200, "OK", received_headers, body=sdp)
    return [
        build_response(100, "Trying", received_headers),
        build_response(180, "Ringing", received_headers, add_to_tag_if_absent=to_tag),
        build_response(486, "Busy Here", received_headers, add_to_tag_if_absent=to_tag)
    ]


def handle_message(received_headers) -> str:
    to_tag = secrets.token_hex(14)
    return build_response(200, "OK", received_headers, add_to_tag_if_absent=to_tag)


def handle_cancel(received_headers) -> str:
    return build_response(200, "OK", received_headers)


def handle_default(received_headers, method) -> str:
    to_tag = secrets.token_hex(14)
    print(f"[!] Method {method} not implemented, sending 501 Not Implemented.", file=sys.stderr)
    return build_response(501, "Not Implemented", received_headers, add_to_tag_if_absent=to_tag)


def handle_received_sip_message(raw_message: bytes, own_ip: str) -> list[str]:
    method, received_headers, _ = parse_sip_message(raw_message)
    if method is None:
        print("[!] Failed to parse SIP message, ignoring.", file=sys.stderr)
        return []

    if method == "OPTIONS":
        responses = [handle_options(received_headers)]
    elif method == "INVITE":
        responses = handle_invite(received_headers, own_ip)
    elif method == "MESSAGE":
        responses = [handle_message(received_headers)]
    elif method == "ACK":
        # ACK requests don't get a response
        responses = []
    elif method == "CANCEL":
        responses = [handle_cancel(received_headers)]
    else:
        responses = [handle_default(received_headers, method)]

    return responses


def conditional_sleep(response: str, logging_info) -> None:
    if response.startswith("SIP/2.0 100"):
        print(f"[<] Sent 100 Trying to {logging_info}, waiting 500ms for next message", file=sys.stderr)
        sleep(0.5)
    elif response.startswith("SIP/2.0 180"):
        print(f"[<] Sent 180 Ringing to {logging_info}, waiting 5s for next message", file=sys.stderr)
        sleep(5)
    elif response.startswith("SIP/2.0 183"):
        print(f"[<] Sent 183 Session Progress to {logging_info}, waiting 10s for next message", file=sys.stderr)
        sleep(10)


def log_timestamp() -> str:
    return datetime.datetime.now().isoformat(sep=" ", timespec="seconds")


def handle_tcp_connection(conn: socket.socket, addr, own_ip) -> None:
    print(f"[+] {log_timestamp()} Connection from {addr}", file=sys.stderr)
    try:
        conn.settimeout(30)
        message_parser = SipStreamParser()
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                print(f"[-] {log_timestamp()} No data read from peer {addr}, stop reading.", file=sys.stderr)
                break

            received_messages = message_parser.feed_and_consume(chunk)
            if received_messages is None:
                continue

            for sip_request in received_messages:
                print(f"[>] {log_timestamp()} Received SIP TCP request from {addr}.", file=sys.stderr)
                responses = handle_received_sip_message(sip_request, own_ip)
                for response in responses:
                    conn.sendall(response.encode())
                    print(f"[<] {log_timestamp()} Sent SIP TCP response to {addr}:\n\n-.-.-\n{response}\n-.-.-\n",
                          file=sys.stderr)
                    conditional_sleep(response, addr)

    except socket.timeout:
        print(f"[-] {log_timestamp()} Timeout, closing connection from {addr}", file=sys.stderr)
    except ConnectionResetError:
        print(f"[-] {log_timestamp()} Connection reset by peer {addr}", file=sys.stderr)
    finally:
        conn.close()
        print(f"[-] {log_timestamp()} Connection closed {addr}", file=sys.stderr)


def run_tcp_server(args):
    inet_family = socket.AF_INET6 if ":" in args.bind_addr else socket.AF_INET
    tcp_sock = socket.socket(inet_family, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_host = args.bind_addr if args.bind_addr != "::" else ""
    tcp_sock.bind((bind_host, args.port))
    tcp_sock.listen(5)
    print(f"SIP server listening on {args.bind_addr}:{args.port}/tcp", file=sys.stderr)

    try:
        while True:
            conn, addr = tcp_sock.accept()
            t = threading.Thread(target=handle_tcp_connection, args=(conn, addr, args.own_ip), daemon=True)
            t.start()
    finally:
        tcp_sock.close()


def read_from_tcp_workaround_socket(tcp_socket: socket.socket, own_ip) -> None:
    response_parser = SipStreamParser()
    while True:
        chunk_resp = tcp_socket.recv(16000)
        if not chunk_resp:
            break
        received_messages = response_parser.feed_and_consume(chunk_resp)
        if received_messages:
            for sip_request in received_messages:
                print(f"[>] {log_timestamp()} Received SIP TCP-workaround request .", file=sys.stderr)
                responses = handle_received_sip_message(sip_request, own_ip)
                for response in responses:
                    tcp_socket.sendall(response.encode())
                    print(
                        f"[<] {log_timestamp()} Sent SIP TCP response to TCP-workaround socket:\n\n-.-.-\n{response}\n-.-.-\n",
                        file=sys.stderr)
                    conditional_sleep(response, "TCP-workaround socket")


def run_tcp_workaround_server(p_cscf_ip: str, server_port: int, client_port: int, args):
    print(f"Starting TCP-workaround server to connect to {p_cscf_ip}:{server_port} from local port {client_port}",
          file=sys.stderr)
    with create_reuse_connection((p_cscf_ip, server_port), source_address=("", client_port)) as tcp_socket:
        print(f"[+] Connected to {p_cscf_ip}:{server_port} from local port {client_port}", file=sys.stderr)
        read_from_tcp_workaround_socket(tcp_socket, args.own_ip)


def handle_udp_packet(data: bytes, addr, server: socket.socket, own_ip: str) -> None:
    print(f"[>] {log_timestamp()} Received SIP UDP request from {addr}.", file=sys.stderr)
    responses = handle_received_sip_message(data, own_ip)
    if len(responses) == 0:
        return

    for response in responses:
        server.sendto(response.encode(), addr)
        print(f"[<] {log_timestamp()} Sent SIP UDP response to {addr}:\n\n-.-.-\n{response}\n-.-.-\n", file=sys.stderr)
        conditional_sleep(response, addr)


def run_udp_server(args):
    inet_family = socket.AF_INET6 if ":" in args.bind_addr else socket.AF_INET
    server = socket.socket(inet_family, socket.SOCK_DGRAM)
    bind_host = args.bind_addr if args.bind_addr != "::" else ""
    server.bind((bind_host, args.port))
    print(f"SIP server listening on {args.bind_addr}:{args.port}/udp", file=sys.stderr)

    try:
        while True:
            data, addr = server.recvfrom(65535)
            t = threading.Thread(target=handle_udp_packet, args=(data, addr, server, args.own_ip), daemon=True)
            t.start()

    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(description="Minimal SIP server over TCP")
    parser.add_argument("--port", type=int, nargs="?", default=5060,
                        help="TCP port to listen on (default: 5060). Ignored when auth file used.")
    parser.add_argument("--own-ip", default=os.getenv(ENV_OWN_IP), help="own IP address (for SDP)")
    parser.add_argument("--bind-addr", default="::", help="Address to bind to (default: ::)")
    parser.add_argument("--proto", choices=["tcp", "udp", "both"], default="both",
                        help="Which transport(s) to listen on (default: both)")
    parser.add_argument("--auth-file", default=os.getenv(ENV_AUTH_STATE_FILE),
                        help="JSON file to read authentication state. Required for TCP-workaround-mode.")
    parser.add_argument("--reverse-tcp", action="store_true",
                        help="Workaround for dubious servers, which send TCP packets on closed connections. Requires --auth-file to be set.")

    args = parser.parse_args()

    if not args.own_ip:
        print(f"[!] Own IP address is required for SDP, set --own-ip or {ENV_OWN_IP}", file=sys.stderr)
        sys.exit(1)

    auth_state = load_auth_state(args.auth_file)
    if auth_state:
        server_port = auth_state.get("ipsec-server", {}).get("port-s")
        client_port = auth_state.get("ipsec-client", {}).get("port-c")
        args.port = auth_state.get("ipsec-client", {}).get("port-s")
        p_cscf_ip = os.getenv(ENV_P_CSCF_IP)
        print(
            f"Loaded an auth file: server_port={server_port}, client_port={client_port}, p_cscf_ip='{p_cscf_ip}', own_server_port={args.port}",
            file=sys.stderr)
    else:
        print(f"No auth state file provided. Used file path: '{args.auth_file}'.", file=sys.stderr)
        server_port = None
        client_port = None
        p_cscf_ip = None

    threads = []
    if args.proto in ("tcp", "both"):
        threads.append(threading.Thread(target=run_tcp_server, args=[args], daemon=True))
        if server_port and client_port and p_cscf_ip and args.reverse_tcp:
            threads.append(
                threading.Thread(target=run_tcp_workaround_server, args=[p_cscf_ip, server_port, client_port, args]))
    if args.proto in ("udp", "both"):
        threads.append(threading.Thread(target=run_udp_server, args=[args], daemon=True))
    for t in threads:
        t.start()

    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
