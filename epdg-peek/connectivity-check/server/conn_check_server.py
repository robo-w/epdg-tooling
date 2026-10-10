#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import socket
import socketserver
import sys
import threading
from dataclasses import dataclass
from typing import Iterable, Sequence


logger = logging.getLogger(__name__)


def is_ipv6_host(host: str) -> bool:
	return ":" in host


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


def build_response(message: bytes) -> bytes | None:
	if message.startswith(b"ping"):
		return b"pong" + message[4:]
	return None


class PingPongTCPHandler(socketserver.BaseRequestHandler):
	def handle(self) -> None:
		while True:
			data = self.request.recv(4096)
			if not data:
				return
			client_host, client_port = self.client_address[:2]
			logger.info("tcp %s:%s received %r", client_host, client_port, data)
			response = build_response(data)
			if response is not None:
				self.request.sendall(response)


class PingPongUDPHandler(socketserver.BaseRequestHandler):
	def handle(self) -> None:
		data = self.request[0]
		socket = self.request[1]
		client_host, client_port = self.client_address[:2]
		logger.info("udp %s:%s received %r", client_host, client_port, data)
		response = build_response(data)
		if response is not None:
			socket.sendto(response, self.client_address)


class ReusableTCPServer(socketserver.ThreadingTCPServer):
	allow_reuse_address = True
	daemon_threads = True


class ReusableUDPServer(socketserver.ThreadingUDPServer):
	allow_reuse_address = True
	daemon_threads = True


class ReusableTCPServerV6(ReusableTCPServer):
	address_family = socket.AF_INET6


class ReusableUDPServerV6(ReusableUDPServer):
	address_family = socket.AF_INET6


@dataclass(frozen=True)
class RunningServer:
	protocol: str
	port: int
	server: socketserver.BaseServer
	thread: threading.Thread


def serve_ports(
	ports: Sequence[int],
	server_factory: type[socketserver.BaseServer],
	handler: type[socketserver.BaseRequestHandler],
	host: str,
	protocol: str,
) -> list[RunningServer]:
	running_servers: list[RunningServer] = []
	for port in ports:
		server = server_factory((host, port), handler)
		thread = threading.Thread(target=server.serve_forever, name=f"{protocol}-{port}", daemon=True)
		thread.start()
		running_servers.append(RunningServer(protocol=protocol, port=port, server=server, thread=thread))
		logger.info("started %s server on %s:%s", protocol, host, port)
	return running_servers


def select_server_factories(host: str) -> tuple[type[socketserver.BaseServer], type[socketserver.BaseServer]]:
	if is_ipv6_host(host):
		return ReusableTCPServerV6, ReusableUDPServerV6
	return ReusableTCPServer, ReusableUDPServer


def shutdown_servers(servers: Iterable[RunningServer]) -> None:
	for running_server in servers:
		running_server.server.shutdown()
		running_server.server.server_close()


def main() -> int:
	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s %(levelname)s %(name)s: %(message)s",
		stream=sys.stderr)

	parser = argparse.ArgumentParser(description="Simple TCP and UDP ping-pong server.")
	parser.add_argument("--host", default="0.0.0.0", help="address to bind to")
	parser.add_argument(
		"--tcp-ports",
		type=parse_port_list,
		default=[7042],
		help="comma-separated TCP ports to listen on",
	)
	parser.add_argument(
		"--udp-ports",
		type=parse_port_list,
		default=[7042],
		help="comma-separated UDP ports to listen on",
	)
	args = parser.parse_args()

	tcp_server_factory, udp_server_factory = select_server_factories(args.host)
	tcp_servers = serve_ports(args.tcp_ports, tcp_server_factory, PingPongTCPHandler, args.host, "tcp")
	udp_servers = serve_ports(args.udp_ports, udp_server_factory, PingPongUDPHandler, args.host, "udp")

	logger.info("server ready; send 'ping' plus any suffix to receive 'pong' plus the same suffix")

	try:
		threading.Event().wait()
	except KeyboardInterrupt:
		pass
	finally:
		shutdown_servers([*tcp_servers, *udp_servers])

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
