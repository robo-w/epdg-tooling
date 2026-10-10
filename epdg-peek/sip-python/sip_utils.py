from __future__ import annotations

import base64
import socket
import sys

from dataclasses import dataclass
from typing import Optional

# Randomly generated IMEI with correct checksum digit for testing.
FIXED_IMEI = "35010188-123456-3"


@dataclass(frozen=True)
class SipTarget:
    host: str
    server_port: int
    client_port: int
    own_server_port: int
    transport: str


class SipParseError(Exception):
    pass


class SipStreamParser:
    HEADER_END = b"\r\n\r\n"

    def __init__(self, max_message_size: int = 2 * 1024 * 1024):
        self.buffer = bytearray()
        self.max_message_size = max_message_size
        self.messages = []

    def feed(self, data: bytes) -> int:
        """Feed arbitrary TCP data and returns the number of messages parsed so far from the stream."""
        self.buffer.extend(data)

        if len(self.buffer) > self.max_message_size:
            raise SipParseError("SIP message exceeds maximum allowed size")

        while True:
            message = self._extract_one()
            if message is None:
                break

            self.messages.append(message)

        return len(self.messages)

    def feed_and_consume(self, data: bytes) -> list[bytes] | None:
        """Feed arbitrary TCP data and return the list of parsed SIP messages, clearing the internal list."""
        available_messages = self.feed(data)
        if available_messages == 0:
            return None
        else:
            return self.consume_messages()

    def consume_messages(self) -> list[bytes]:
        """Return the list of parsed SIP messages and clear the internal list."""
        messages = self.messages.copy()
        self.messages.clear()
        return messages

    def peek_messages(self) -> list[bytes]:
        """Return the list of parsed SIP messages."""
        return self.messages.copy()

    def get_unparsed_data(self) -> bytes:
        """Return any unparsed data remaining in the buffer."""
        return bytes(self.buffer)

    def _extract_one(self) -> Optional[bytes]:
        header_end = self.buffer.find(self.HEADER_END)

        # We don't yet have the complete header section.
        if header_end == -1:
            return None

        header_end += len(self.HEADER_END)

        header_bytes = bytes(self.buffer[:header_end])

        try:
            content_length = self._get_content_length(header_bytes)
        except ValueError as e:
            raise SipParseError(str(e)) from e

        total_length = header_end + content_length

        if total_length > self.max_message_size:
            raise SipParseError("SIP message exceeds maximum allowed size")

        # Header is complete, but body isn't.
        if len(self.buffer) < total_length:
            return None

        # Extract exactly one message.
        message = bytes(self.buffer[:total_length])

        # Leave bytes belonging to the next SIP message in the buffer.
        del self.buffer[:total_length]

        return message

    @staticmethod
    def _get_content_length(headers: bytes) -> int:
        # SIP header syntax is ASCII-compatible.
        try:
            text = headers.decode("ascii")
        except UnicodeDecodeError as e:
            raise ValueError("Invalid non-ASCII bytes in SIP headers") from e

        content_length = None
        content_length_str = get_sip_header(text, "Content-Length")
        if content_length_str is not None:
            try:
                n = int(content_length_str)
            except ValueError:
                raise ValueError("Invalid Content-Length")

            if n < 0:
                raise ValueError("Negative Content-Length")

            content_length = n

        return content_length if content_length is not None else 0


def get_sip_header(message: str, header_name: str) -> str | None:
    header_name = header_name.lower()

    for line in message.splitlines():
        if ":" not in line:
            continue

        name, value = line.split(":", 1)

        if name.strip().lower() == header_name:
            return value.strip()

    return None


def create_contact_header(contact_uri: str, imei: str, sms_support: bool = True) -> str:
    contact_header = f"Contact: {contact_uri};+sip.instance=\"<urn:gsma:imei:{imei}>\";q=1.0;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\""
    if sms_support:
        contact_header += ";+g.3gpp.smsip"

    return contact_header


def create_reuse_connection(address, timeout: float | None = None, source_address=None,
                            all_errors=False) -> socket.socket:
    """
    Drop-in replacement for socket.create_connection(), identical in
    behavior except that SO_REUSEADDR is set on the socket before
    bind()/connect().
    """
    host, port = address
    exceptions = []
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, _, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # THIS LINE was added
            if timeout is not None:
                sock.settimeout(timeout)
            if source_address is not None:
                sock.bind(source_address)
            sock.connect(sa)
            # Break explicitly a reference cycle
            exceptions.clear()
            return sock

        except OSError as exc:
            if not all_errors:
                exceptions.clear()  # raise only the last error
            exceptions.append(exc)
            if sock is not None:
                sock.close()

    if len(exceptions):
        try:
            if not all_errors:
                raise exceptions[0]
            raise ExceptionGroup("create_connection failed", exceptions)
        finally:
            # Break explicitly a reference cycle
            exceptions.clear()
    else:
        raise OSError("getaddrinfo returns an empty list")


def send_request(target: SipTarget, request: bytes, timeout: float | None, expected_responses: int = 1,
                 break_on_final_response: bool = False) -> tuple[list[bytes], bytes]:
    address_family = socket.AF_INET6 if ":" in target.host else socket.AF_INET

    if target.transport == "tcp":
        with create_reuse_connection((target.host, target.server_port), source_address=("", target.client_port),
                                     timeout=timeout) as tcp_socket:
            tcp_socket.sendall(request)
            response_parser = SipStreamParser()
            while True:
                try:
                    chunk_resp = tcp_socket.recv(16000)
                    if not chunk_resp:
                        break
                    received_messages = response_parser.feed(chunk_resp)

                    if expected_responses > 0 and received_messages >= expected_responses:
                        print(
                            f"Received {received_messages} SIP responses, expected {expected_responses}. Stop reading from stream.",
                            file=sys.stderr)
                        break

                    if break_on_final_response:
                        try:
                            status_codes = [int(msg.decode(errors="replace").splitlines()[0].split(" ")[1]) for msg in
                                            response_parser.peek_messages()]
                            if any(code >= 200 for code in status_codes):
                                print(f"Received a final SIP response, stopping to wait for more messages.",
                                      file=sys.stderr)
                                break
                        except Exception as e:
                            print(
                                f"Failed to parse status codes from received messages: {e}. Continuing to read from stream.",
                                file=sys.stderr)

                except socket.timeout:
                    print("Socket timeout while waiting for response.", file=sys.stderr)
                    break

            return response_parser.peek_messages(), response_parser.get_unparsed_data()
    else:
        with socket.socket(address_family, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.settimeout(timeout)
            udp_socket.sendto(request, (target.host, target.server_port))

            response_parser = SipStreamParser()
            received_responses = 0
            while expected_responses <= 0 or received_responses < expected_responses:
                response, _ = udp_socket.recvfrom(16000)
                if not response:
                    break

                received_responses = response_parser.feed(response)

            return response_parser.peek_messages(), response_parser.get_unparsed_data()


def build_sip_target_from_auth_state(auth_state: dict, host: str, transport: str = "tcp") -> SipTarget:
    server_port = auth_state.get("ipsec-server", {}).get("port-s")
    client_port = auth_state.get("ipsec-client", {}).get("port-c")
    own_server_port = auth_state.get("ipsec-client", {}).get("port-s")
    if server_port and client_port and own_server_port:
        print(f"Using stored server port {server_port} and client port {client_port} from auth state.", file=sys.stderr)
        target = SipTarget(host=host, server_port=server_port, client_port=client_port, own_server_port=own_server_port,
                           transport=transport)
    else:
        raise ValueError("Missing port information in auth state to build SipTarget.")

    return target


def get_message_without_body(raw_message: bytes) -> tuple[str | None, bytes]:
    text = raw_message.decode(errors="replace")
    lines = text.splitlines(keepends=True)
    if not lines or not lines[0]:
        print("[!] Failed to read first line from received SIP message.", file=sys.stderr)
        return None, b""

    header_lines = ""
    for line in lines:
        header_lines += line
        if not line.strip():
            break  # End of headers

    return header_lines, raw_message[len(header_lines.encode()):]


def parse_sip_message(raw_message: bytes) -> tuple[str | None, dict, bytes]:
    non_body_lines, body_bytes = get_message_without_body(raw_message)
    if non_body_lines is None:
        return None, {}, b""

    lines = non_body_lines.splitlines()
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) < 3:
        print("[!] Failed to parse request line.", file=sys.stderr)
        return None, {}, b""

    method = parts[0]
    print(
        f"[>] Received SIP {method} request:\n\n~~~~~\n{non_body_lines}\n~~~~~\nBody Base64: {base64.b64encode(body_bytes).decode()}\n",
        file=sys.stderr)

    headers = {}
    for line in lines[1:]:
        if not line.strip():
            break  # End of headers
        if ":" not in line:
            continue

        key, _, value = line.partition(":")
        if key in headers:
            print(f"[!] Duplicate header {key} found, appending value.", file=sys.stderr)
            headers[key.strip().lower()] += ", " + value.strip()
        else:
            headers[key.strip().lower()] = value.strip()

    return method, headers, body_bytes
