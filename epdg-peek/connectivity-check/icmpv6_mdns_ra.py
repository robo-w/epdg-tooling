#!/usr/bin/env python3

import ipaddress
import socket
import struct

# Parameters for mDNS announcement
NAME = "teapot.local"
ADDR = "::1"

# Parameter for router solicitation
IFACE = "tun23"

def encode_name(name):
    return b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in name.rstrip(".").split(".")
    ) + b"\x00"

def create_mdns_packet():
    # DNS header
    # ID = 0
    # Flags = 0x8400 (QR=1, AA=1)
    # QDCOUNT = 0
    # ANCOUNT = 1
    # NSCOUNT = 0
    # ARCOUNT = 0
    packet = struct.pack("!HHHHHH",
        0,          # ID
        0x8400,     # Flags: response + authoritative
        0,          # Questions
        1,          # Answers
        0,
        0,
    )

    # AAAA resource record
    packet += encode_name(NAME)
    packet += struct.pack("!HHI",
        28,         # TYPE = AAAA
        1,          # CLASS = IN
        5,          # TTL
    )
    rdata = ipaddress.IPv6Address(ADDR).packed
    packet += struct.pack("!H", len(rdata))
    packet += rdata

    return packet

def send_mdns_announcement():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    mdns_packet = create_mdns_packet()
    sock.sendto(mdns_packet, ("ff02::fb", 5353))

    print("Sent mDNS announcement for", NAME, "->", ADDR)

def create_router_solicitation_packet():
    # ICMPv6 Router Solicitation
    # Type = 133
    # Code = 0
    # Checksum = 0 (computed by the kernel on Linux for raw ICMPv6 sockets)
    # Reserved = 0
    packet = struct.pack("!BBHI",
        133,    # Type: Router Solicitation
        0,      # Code
        0,      # Checksum
        0       # Reserved
    )

    return packet

def send_router_solicitation():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)

    # Send through the desired interface
    sock.setsockopt(
        socket.IPPROTO_IPV6,
        socket.IPV6_MULTICAST_IF,
        socket.if_nametoindex(IFACE),
    )

    # Restrict the hop limit to 255 as required by RFC 4861
    sock.setsockopt(
        socket.IPPROTO_IPV6,
        socket.IPV6_MULTICAST_HOPS,
        255,
    )

    ra_packet = create_router_solicitation_packet()
    # Destination: all routers
    sock.sendto(ra_packet, ("ff02::2", 0, 0, socket.if_nametoindex(IFACE)))

    print("Sent Router Solicitation")

if __name__ == "__main__":
    send_mdns_announcement()
    send_router_solicitation()
