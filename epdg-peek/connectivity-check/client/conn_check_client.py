#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import socket
import sys
import uuid
from typing import Sequence


logger = logging.getLogger(__name__)


def parse_port_list(value: str) -> list[int]:
	ports: list[int] = []
	for item in value.split(","):
		item = item.strip()
		if not item:
			continue
		port = int(item)
		if port < 1 or port > 65535:
			raise argparse.ArgumentTypeError(f"invalid port: {port}")
		ports.append(port)
	if not ports:
		raise argparse.ArgumentTypeError("at least one port is required")
	return ports


def build_message(port: int) -> bytes:
	return f"ping {port} {uuid.uuid4()}".encode("ascii")


def send_tcp_message(host: str, port: int, message: bytes, timeout: float) -> bytes:
	with socket.create_connection((host, port), timeout=timeout) as connection:
		connection.settimeout(timeout)
		connection.sendall(message)
		connection.shutdown(socket.SHUT_WR)
		response = bytearray()
		while True:
			chunk = connection.recv(4096)
			if not chunk:
				break
			response.extend(chunk)
	return bytes(response)


def send_udp_message(host: str, port: int, message: bytes, timeout: float) -> bytes:
	address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
	with socket.socket(address_family, socket.SOCK_DGRAM) as udp_socket:
		udp_socket.settimeout(timeout)
		udp_socket.sendto(message, (host, port))
		response, _ = udp_socket.recvfrom(4096)
		return response


def is_expected_response(message: bytes, response: bytes) -> bool:
	return response == b"pong" + message[4:]


def run_tcp_checks(host: str, ports: Sequence[int], timeout: float) -> list[str]:
	probe_results: list[str] = []
	for port in ports:
		message = build_message(port)
		logger.info("tcp sending to %s:%s payload=%r", host, port, message)
		try:
			tcp_response = send_tcp_message(host, port, message, timeout)
		except ConnectionRefusedError:
			logger.warning("tcp port closed at %s:%s", host, port)
			probe_results.append(f"TCP,{port},port_filtered")
			continue
		except socket.timeout:
			logger.warning("tcp request timed out at %s:%s", host, port)
			probe_results.append(f"TCP,{port},timeout")
			continue

		logger.info("tcp received from %s:%s payload=%r", host, port, tcp_response)
		if not tcp_response:
			logger.warning("tcp port returned no response at %s:%s", host, port)
			probe_results.append(f"TCP,{port},no_response")
		elif not is_expected_response(message, tcp_response):
			logger.warning("tcp port returned unexpected response at %s:%s: %r", host, port, tcp_response)
			probe_results.append(f"TCP,{port},unexpected_response")
		else:
			logger.info("tcp successful roundtrip to %s:%s payload=%r response=%r", host, port, message, tcp_response)
			probe_results.append(f"TCP,{port},success")

	return probe_results


def run_udp_checks(host: str, ports: Sequence[int], timeout: float) -> list[str]:
	probe_results: list[str] = []
	for port in ports:
		message = build_message(port)
		logger.info("udp sending to %s:%s payload=%r", host, port, message)
		try:
			udp_response = send_udp_message(host, port, message, timeout)
		except socket.timeout:
			logger.warning("udp request timed out at %s:%s", host, port)
			probe_results.append(f"UDP,{port},timeout")
			continue

		logger.info("udp received from %s:%s payload=%r", host, port, udp_response)
		if not udp_response:
			logger.warning("udp port returned no response at %s:%s", host, port)
			probe_results.append(f"UDP,{port},no_response")
		elif not is_expected_response(message, udp_response):
			logger.warning("udp port returned unexpected response at %s:%s: %r", host, port, udp_response)
			probe_results.append(f"UDP,{port},unexpected_response")
		else:
			logger.info("udp successful roundtrip to %s:%s payload=%r response=%r", host, port, message, udp_response)
			probe_results.append(f"UDP,{port},success")

	return probe_results


def main() -> int:
	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s %(levelname)s %(name)s: %(message)s",
		stream=sys.stderr)

	parser = argparse.ArgumentParser(description="Connectivity check client for TCP and UDP ports.")
	parser.add_argument("--host", required=True, help="target host to connect to")
	parser.add_argument(
		"--tcp-ports",
		type=parse_port_list,
		default=[7042],
		help="comma-separated TCP ports to probe",
	)
	parser.add_argument(
		"--udp-ports",
		type=parse_port_list,
		default=[7042],
		help="comma-separated UDP ports to probe",
	)
	parser.add_argument("--timeout", type=float, default=1.0, help="socket timeout in seconds")
	args = parser.parse_args()

	probe_results = [
		*run_tcp_checks(args.host, args.tcp_ports, args.timeout),
		*run_udp_checks(args.host, args.udp_ports, args.timeout)]

	if probe_results:
		logger.info("connectivity check completed with %d successful probe(s)", len(probe_results))
		print("Protocol,Port,Result")
		for probe in probe_results:
			print(probe)

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
