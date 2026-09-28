#!/usr/bin/env python3
"""Generate a deterministic, non-routable PCAP for the network-forensics lab."""

from __future__ import annotations

import argparse
import socket
import struct
from pathlib import Path
from typing import Sequence


BASE_EPOCH = 1_790_604_000
CLIENT = "10.10.20.15"
DNS_SERVER = "192.0.2.53"
PORTAL = "198.51.100.10"
BEACON_SERVER = "203.0.113.50"
TRANSFER_SERVER = "203.0.113.77"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload: bytes) -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + payload


def ipv4(src: str, dst: str, protocol: int, payload: bytes, ident: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident,
        0x4000,
        64,
        protocol,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return ethernet(header + payload)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int) -> bytes:
    segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ipv4(src, dst, 17, segment, ident)


def tcp(src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int, sequence: int) -> bytes:
    offset_flags = (5 << 12) | 0x018
    segment = struct.pack("!HHIIHHHH", sport, dport, sequence, 1, offset_flags, 8192, 0, 0) + payload
    return ipv4(src, dst, 6, segment, ident)


def dns_query(name: str, query_id: int) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def build_packets() -> tuple[tuple[int, bytes], ...]:
    packets: list[tuple[int, bytes]] = []
    ident = 1

    def add(offset: int, frame: bytes) -> None:
        nonlocal ident
        packets.append((BASE_EPOCH + offset, frame))
        ident += 1

    add(0, udp(CLIENT, DNS_SERVER, 53000, 53, dns_query("portal.example", 1), ident))
    add(2, tcp(CLIENT, PORTAL, 51000, 80, b"GET / HTTP/1.1\r\nHost: portal.example\r\n\r\n", ident, 1))
    add(5, udp(CLIENT, DNS_SERVER, 53001, 53, dns_query("cdn-sync.example", 2), ident))
    add(7, tcp(CLIENT, BEACON_SERVER, 51001, 80, b"GET /download/loader.bin HTTP/1.1\r\nHost: cdn-sync.example\r\n\r\n", ident, 1))
    add(10, tcp(CLIENT, PORTAL, 51002, 80, b"GET /profile HTTP/1.1\r\nHost: portal.example\r\nAuthorization: Basic REDACTED-LAB-VALUE\r\n\r\n", ident, 1))
    for sequence, offset in enumerate((20, 80, 140, 200, 260), start=1):
        payload = f"POST /checkin HTTP/1.1\r\nHost: cdn-sync.example\r\nContent-Length: 4\r\n\r\np{sequence:03d}".encode("ascii")
        add(offset, tcp(CLIENT, BEACON_SERVER, 52000, 8080, payload, ident, sequence))
    for sequence, offset in enumerate((300, 302, 304, 306), start=1):
        add(offset, tcp(CLIENT, TRANSFER_SERVER, 53000, 443, b"X" * 1300, ident, sequence))
    return tuple(packets)


def write_pcap(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in build_packets():
            handle.write(struct.pack("<IIII", timestamp, 0, len(frame), len(frame)))
            handle.write(frame)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    write_pcap(args.output)
    print(f"wrote {len(build_packets())} packets to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
