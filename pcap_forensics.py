#!/usr/bin/env python3
"""Analyze a classic PCAP and reconstruct a synthetic network incident."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import struct
import unicodedata
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


MAX_PACKET_BYTES = 1_048_576
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 100_000
SUSPICIOUS_DOMAINS = {"cdn-sync.example"}
DOWNLOAD_EXTENSIONS = (".bin", ".dll", ".exe", ".ps1", ".scr")


class PcapError(ValueError):
    """Raised when a capture cannot be parsed safely."""


@dataclass(frozen=True)
class Packet:
    timestamp: datetime
    source: str
    destination: str
    protocol: str
    source_port: int
    destination_port: int
    payload: bytes


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    timestamp: datetime
    source: str
    destination: str
    title: str
    evidence: str
    mitre_technique: str


@dataclass(frozen=True)
class Investigation:
    severity: str
    packet_count: int
    findings: tuple[Finding, ...]
    internal_hosts: tuple[str, ...]
    external_hosts: tuple[str, ...]
    domains: tuple[str, ...]


def _internal(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return any(ip in network for network in (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ))


def _parse_frame(frame: bytes, timestamp: datetime) -> Packet | None:
    if len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
        return None
    ip_start = 14
    version_ihl = frame[ip_start]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(frame) < ip_start + ihl:
        raise PcapError("invalid IPv4 header length")
    total_length = struct.unpack("!H", frame[ip_start + 2:ip_start + 4])[0]
    if total_length < ihl or len(frame) < ip_start + total_length:
        raise PcapError("truncated IPv4 packet")
    protocol = frame[ip_start + 9]
    source = str(ipaddress.ip_address(frame[ip_start + 12:ip_start + 16]))
    destination = str(ipaddress.ip_address(frame[ip_start + 16:ip_start + 20]))
    transport = frame[ip_start + ihl:ip_start + total_length]
    if protocol == 6:
        if len(transport) < 20:
            raise PcapError("truncated TCP header")
        source_port, destination_port = struct.unpack("!HH", transport[:4])
        offset = (transport[12] >> 4) * 4
        if offset < 20 or len(transport) < offset:
            raise PcapError("invalid TCP data offset")
        return Packet(timestamp, source, destination, "TCP", source_port, destination_port, transport[offset:])
    if protocol == 17:
        if len(transport) < 8:
            raise PcapError("truncated UDP header")
        source_port, destination_port, length = struct.unpack("!HHH", transport[:6])
        if length < 8 or len(transport) < length:
            raise PcapError("invalid UDP length")
        return Packet(timestamp, source, destination, "UDP", source_port, destination_port, transport[8:length])
    return None


def read_pcap(path: Path) -> tuple[Packet, ...]:
    """Read Ethernet IPv4 TCP/UDP packets from a classic PCAP."""
    try:
        with path.open("rb") as capture:
            data = capture.read(MAX_CAPTURE_BYTES + 1)
    except OSError as exc:
        raise PcapError(f"unable to read {path}: {exc}") from exc
    if len(data) > MAX_CAPTURE_BYTES:
        raise PcapError(f"capture exceeds the {MAX_CAPTURE_BYTES // (1024 * 1024)} MiB input limit")
    if len(data) < 24:
        raise PcapError("capture is missing the global header")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, divisor = "<", 1_000_000
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, divisor = ">", 1_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, divisor = "<", 1_000_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, divisor = ">", 1_000_000_000
    else:
        raise PcapError("unsupported capture format or byte order")
    _, major, minor, _, _, snaplen, linktype = struct.unpack(f"{endian}IHHIIII", data[:24])
    if (major, minor) != (2, 4) or snaplen <= 0 or linktype != 1:
        raise PcapError("only classic Ethernet PCAP version 2.4 is supported")

    packets: list[Packet] = []
    cursor = 24
    record_count = 0
    while cursor < len(data):
        record_count += 1
        if record_count > MAX_RECORDS:
            raise PcapError(f"capture exceeds the {MAX_RECORDS} record limit")
        if len(data) - cursor < 16:
            raise PcapError("truncated packet record header")
        seconds, fraction, captured, original = struct.unpack(f"{endian}IIII", data[cursor:cursor + 16])
        cursor += 16
        if captured > MAX_PACKET_BYTES or captured > original or captured > snaplen:
            raise PcapError("unsafe or inconsistent captured length")
        if len(data) - cursor < captured:
            raise PcapError("truncated packet record")
        timestamp = datetime.fromtimestamp(seconds + fraction / divisor, tz=timezone.utc)
        packet = _parse_frame(data[cursor:cursor + captured], timestamp)
        cursor += captured
        if packet is not None:
            packets.append(packet)
    return tuple(packets)


def dns_query_name(payload: bytes) -> str | None:
    if len(payload) < 17:
        return None
    questions = struct.unpack("!H", payload[4:6])[0]
    if questions < 1:
        return None
    labels: list[str] = []
    cursor = 12
    while cursor < len(payload):
        length = payload[cursor]
        cursor += 1
        if length == 0:
            break
        if length > 63 or cursor + length > len(payload):
            return None
        try:
            labels.append(payload[cursor:cursor + length].decode("ascii"))
        except UnicodeDecodeError:
            return None
        cursor += length
    return ".".join(labels).lower() if labels else None


def http_request(payload: bytes) -> tuple[str, dict[str, str]] | None:
    try:
        text = payload.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None
    lines = text.split("\r\n")
    parts = lines[0].split()
    if len(parts) != 3 or parts[0] not in {"GET", "POST", "PUT", "DELETE", "HEAD"} or not parts[2].startswith("HTTP/"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    return f"{parts[0]} {parts[1]}", headers


def analyze(packets: Sequence[Packet]) -> Investigation:
    findings: list[Finding] = []
    domains: set[str] = set()
    beacon_groups: dict[tuple[str, str, int], list[Packet]] = defaultdict(list)
    transfer_groups: dict[tuple[str, str], list[Packet]] = defaultdict(list)

    for packet in packets:
        if packet.protocol == "UDP" and packet.destination_port == 53:
            domain = dns_query_name(packet.payload)
            if domain:
                domains.add(domain)
                if domain in SUSPICIOUS_DOMAINS:
                    findings.append(Finding("NET-001", "high", packet.timestamp, packet.source, packet.destination, "Suspicious DNS lookup", f"query={domain}", "T1071.004"))
        request = http_request(packet.payload) if packet.protocol == "TCP" else None
        if request:
            request_line, headers = request
            path = request_line.split(" ", 1)[1].lower()
            if path.endswith(DOWNLOAD_EXTENSIONS):
                findings.append(Finding("NET-002", "high", packet.timestamp, packet.source, packet.destination, "Executable-like HTTP download", f"request={request_line}; host={headers.get('host', 'unknown')}", "T1105"))
            if headers.get("authorization", "").lower().startswith("basic "):
                findings.append(Finding("NET-003", "medium", packet.timestamp, packet.source, packet.destination, "Cleartext Basic authorization observed", f"request={request_line}; credential-value=redacted", "T1557"))
            if request_line == "POST /checkin":
                beacon_groups[(packet.source, packet.destination, packet.destination_port)].append(packet)
        if _internal(packet.source) and not _internal(packet.destination) and packet.protocol == "TCP" and packet.payload:
            transfer_groups[(packet.source, packet.destination)].append(packet)

    for (source, destination, port), group in beacon_groups.items():
        ordered = sorted(group, key=lambda packet: packet.timestamp)
        intervals = [(right.timestamp - left.timestamp).total_seconds() for left, right in zip(ordered, ordered[1:])]
        if len(intervals) >= 3 and max(abs(interval - 60) for interval in intervals) <= 3:
            findings.append(Finding("NET-004", "critical", ordered[0].timestamp, source, destination, "Periodic command-and-control beacon", f"destination_port={port}; checkins={len(ordered)}; interval_seconds=60", "T1071.001"))

    for (source, destination), group in transfer_groups.items():
        ordered = sorted(group, key=lambda packet: packet.timestamp)
        right = 0
        total = 0
        for start, packet in enumerate(ordered):
            while right < len(ordered) and (ordered[right].timestamp - packet.timestamp).total_seconds() <= 10:
                total += len(ordered[right].payload)
                right += 1
            if total >= 4096:
                findings.append(Finding("NET-005", "high", ordered[start].timestamp, source, destination, "High-volume outbound transfer", f"payload_bytes={total}; window_seconds=10", "T1041"))
                break
            total -= len(packet.payload)

    unique_findings = {finding.rule_id: finding for finding in findings}
    ordered_findings = tuple(sorted(unique_findings.values(), key=lambda finding: (finding.timestamp, finding.rule_id)))
    severity = "critical" if any(finding.severity == "critical" for finding in ordered_findings) and len(ordered_findings) >= 4 else "high" if ordered_findings else "informational"
    internal_hosts = sorted({address for packet in packets for address in (packet.source, packet.destination) if _internal(address)})
    external_hosts = sorted({address for packet in packets for address in (packet.source, packet.destination) if not _internal(address)})
    return Investigation(severity, len(packets), ordered_findings, tuple(internal_hosts), tuple(external_hosts), tuple(sorted(domains)))


def _cell(value: object) -> str:
    text = "".join(
        " " if unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"} else char
        for char in str(value)
    )
    text = re.sub(r"(?i)https?://", lambda match: "hxxps://" if match.group(0).lower() == "https://" else "hxxp://", text)
    text = re.sub(r"(?i)\b(?!hxxps?)([a-z][a-z0-9+.-]*):(?=//|[a-z])", r"\1[:]", text)
    text = text.replace(".", "[.]")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for char in "\\`*_{}[]()#!|<>":
        text = text.replace(char, "\\" + char)
    return text


def render_markdown(investigation: Investigation, source: str) -> str:
    lines = [
        "# Network Forensics Investigation Report",
        "",
        f"- Evidence: {_cell(source)}",
        f"- Packets analyzed: **{investigation.packet_count}**",
        f"- Incident severity: **{_cell(investigation.severity.upper())}**",
        f"- Findings: **{len(investigation.findings)}**",
        "",
        "## Timeline",
        "",
        "| Time (UTC) | Rule | Severity | Source | Destination | Finding | Evidence |",
        "|---|---|---|---|---|---|---|",
    ]
    for finding in investigation.findings:
        lines.append("| " + " | ".join(_cell(value) for value in (
            finding.timestamp.isoformat(), finding.rule_id, finding.severity, finding.source,
            finding.destination, finding.title, finding.evidence,
        )) + " |")
    lines.extend([
        "", "## Indicators", "",
        f"- Internal hosts: {', '.join(_cell(value) for value in investigation.internal_hosts) or 'None'}",
        f"- External hosts: {', '.join(_cell(value) for value in investigation.external_hosts) or 'None'}",
        f"- Queried domains: {', '.join(_cell(value) for value in investigation.domains) or 'None'}",
        "", "## Recommended Response", "",
        "1. Isolate the affected workstation while preserving volatile evidence.",
        "2. Block confirmed malicious destinations and domains after validation.",
        "3. Acquire endpoint telemetry and correlate process, DNS, and proxy events.",
        "4. Reset exposed credentials and prohibit cleartext authentication.",
        "5. Scope for other hosts exhibiting the same beacon interval or indicators.",
        "",
    ])
    return "\n".join(lines)


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("summary", "json"), default="summary")
    parser.add_argument("--fail-on-incident", action="store_true")
    args = parser.parse_args(argv)
    try:
        investigation = analyze(read_pcap(args.capture))
    except PcapError as exc:
        print(f"error: {exc}")
        return 2
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(render_markdown(investigation, args.capture.name), encoding="utf-8")
    if args.format == "json":
        print(json.dumps(asdict(investigation), indent=2, sort_keys=True, default=_json_default))
    else:
        print(f"packets={investigation.packet_count} findings={len(investigation.findings)} severity={investigation.severity}")
    return 1 if args.fail_on_incident and investigation.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
