import io
import json
import struct
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from tempfile import NamedTemporaryFile
from unittest.mock import patch
from contextlib import redirect_stdout
from pathlib import Path

from generate_synthetic_pcap import build_packets, dns_query, write_pcap
from pcap_forensics import (
    PcapError,
    Finding,
    Investigation,
    Packet,
    analyze,
    dns_query_name,
    http_request,
    main,
    read_pcap,
    render_markdown,
)
import pcap_forensics as pcap


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "samples" / "synthetic-incident.pcap"


class PcapForensicsTests(unittest.TestCase):
    def test_capture_byte_limit_is_enforced(self) -> None:
        with NamedTemporaryFile(dir=ROOT / "reports", suffix=".pcap", delete=False) as scratch:
            scratch.write(b"x" * 33)
            path = Path(scratch.name)
        self.addCleanup(path.unlink, missing_ok=True)
        original_open = Path.open
        requested_sizes = []

        class TrackingReader:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def __enter__(self):
                self.wrapped.__enter__()
                return self

            def __exit__(self, *args):
                return self.wrapped.__exit__(*args)

            def read(self, size=-1):
                requested_sizes.append(size)
                return self.wrapped.read(size)

        def tracking_open(file_path, *args, **kwargs):
            return TrackingReader(original_open(file_path, *args, **kwargs))

        with patch.object(pcap, "MAX_CAPTURE_BYTES", 32), \
             patch.object(Path, "open", tracking_open):
            with self.assertRaisesRegex(PcapError, "input limit"):
                read_pcap(path)
        self.assertEqual(requested_sizes, [33])

    def test_record_limit_is_enforced(self) -> None:
        path = ROOT / "reports" / ".test-record-limit.pcap"
        self.addCleanup(path.unlink, missing_ok=True)
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        empty_record = struct.pack("<IIII", 1, 0, 0, 0)
        path.write_bytes(header + empty_record * 100_001)
        with self.assertRaisesRegex(PcapError, "record limit"):
            read_pcap(path)

    def test_generator_builds_fourteen_packets(self) -> None:
        self.assertEqual(len(build_packets()), 14)

    def test_capture_contains_fourteen_parsed_packets(self) -> None:
        self.assertEqual(len(read_pcap(CAPTURE)), 14)

    def test_first_packet_is_dns(self) -> None:
        packet = read_pcap(CAPTURE)[0]
        self.assertEqual((packet.protocol, packet.destination_port), ("UDP", 53))
        self.assertEqual(packet.source, "10.10.20.15")

    def test_dns_query_parser(self) -> None:
        self.assertEqual(dns_query_name(dns_query("test.example", 4)), "test.example")

    def test_dns_query_parser_rejects_short_payload(self) -> None:
        self.assertIsNone(dns_query_name(b"short"))

    def test_http_request_parser(self) -> None:
        result = http_request(b"GET /sample HTTP/1.1\r\nHost: test.example\r\n\r\n")
        self.assertEqual(result, ("GET /sample", {"host": "test.example"}))

    def test_http_request_parser_rejects_binary(self) -> None:
        self.assertIsNone(http_request(b"\x00\x01\x02"))

    def test_investigation_is_critical(self) -> None:
        self.assertEqual(analyze(read_pcap(CAPTURE)).severity, "critical")

    def test_expected_detection_rules(self) -> None:
        rules = {finding.rule_id for finding in analyze(read_pcap(CAPTURE)).findings}
        self.assertEqual(rules, {"NET-001", "NET-002", "NET-003", "NET-004", "NET-005"})

    def test_expected_domains_are_extracted(self) -> None:
        self.assertEqual(analyze(read_pcap(CAPTURE)).domains, ("cdn-sync.example", "portal.example"))

    def test_internal_host_is_identified(self) -> None:
        self.assertEqual(analyze(read_pcap(CAPTURE)).internal_hosts, ("10.10.20.15",))

    def test_credential_value_is_redacted(self) -> None:
        finding = next(item for item in analyze(read_pcap(CAPTURE)).findings if item.rule_id == "NET-003")
        self.assertIn("redacted", finding.evidence)
        self.assertNotIn("REDACTED-LAB-VALUE", finding.evidence)

    def test_short_beacon_series_does_not_trigger(self) -> None:
        packets = read_pcap(CAPTURE)
        reduced = tuple(packet for index, packet in enumerate(packets) if index not in {8, 9})
        rules = {finding.rule_id for finding in analyze(reduced).findings}
        self.assertNotIn("NET-004", rules)

    def test_subthreshold_transfer_does_not_trigger(self) -> None:
        packets = read_pcap(CAPTURE)[:-1]
        rules = {finding.rule_id for finding in analyze(packets).findings}
        self.assertNotIn("NET-005", rules)

    def test_transfer_window_includes_packet_exactly_ten_seconds_later(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        packets = (
            Packet(start, "10.0.0.1", "203.0.113.8", "TCP", 40000, 443, b"a" * 2048),
            Packet(start + timedelta(seconds=10), "10.0.0.1", "203.0.113.8", "TCP", 40000, 443, b"b" * 2048),
            Packet(start + timedelta(seconds=10, milliseconds=1), "10.0.0.1", "203.0.113.8", "TCP", 40000, 443, b"c" * 4096),
        )
        finding = next(item for item in analyze(packets).findings if item.rule_id == "NET-005")
        self.assertEqual(finding.timestamp, start)
        self.assertEqual(finding.evidence, "payload_bytes=4096; window_seconds=10")

    def test_transfer_selects_earliest_qualifying_window_start(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        packets = (
            Packet(start, "10.0.0.1", "203.0.113.8", "TCP", 40000, 443, b"a" * 1000),
            Packet(start + timedelta(seconds=10), "10.0.0.1", "203.0.113.8", "TCP", 40000, 443, b"b" * 1000),
            Packet(start + timedelta(seconds=10, milliseconds=1), "10.0.0.1", "203.0.113.8", "TCP", 40000, 443, b"c" * 3096),
        )
        finding = next(item for item in analyze(packets).findings if item.rule_id == "NET-005")
        self.assertEqual(finding.timestamp, start + timedelta(seconds=10))

    def test_many_repeated_subthreshold_packets_do_not_trigger(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        packets = tuple(
            Packet(start + timedelta(seconds=11 * index), "10.0.0.1", "203.0.113.8", "TCP", 40000, 443, b"x")
            for index in range(20_000)
        )
        self.assertNotIn("NET-005", {item.rule_id for item in analyze(packets).findings})

    def test_report_contains_timeline(self) -> None:
        report = render_markdown(analyze(read_pcap(CAPTURE)), "sample|capture.pcap")
        self.assertIn("## Timeline", report)
        self.assertIn("NET-004", report)

    def test_markdown_escapes_untrusted_fields_and_defangs_links(self) -> None:
        timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
        finding = Finding("NET-999", "high", timestamp, "[x](https://evil.example)", "203.0.113.1",
                          "**title** _x_\n## forged\u202e", "evidence | [x](http://evil.example) <script>bad</script> <tag>\u0085", "T1000")
        investigation = Investigation("high", 1, (finding,), (), (), ("evil.example",))
        report = render_markdown(investigation, "[x](https://evil.example)\n<script>bad</script>")
        self.assertNotIn("[x](https://evil.example)", report)
        self.assertNotIn("\n## forged", report)
        self.assertNotIn("<script>", report)
        self.assertNotIn("<tag>", report)
        self.assertNotIn("\u202e", report)
        self.assertNotIn("\u0085", report)
        self.assertIn(r"\*\*title\*\* \_x\_", report)
        self.assertIn("hxxps://evil", report)
        self.assertIn("hxxp://evil", report)
        raw_json = json.dumps(asdict(investigation), default=pcap._json_default)
        self.assertIn("<script>bad</script>", raw_json)
        self.assertIn("**title**", raw_json)

    def test_generated_capture_is_reproducible(self) -> None:
        output = ROOT / "reports" / ".test-generated.pcap"
        self.addCleanup(output.unlink, missing_ok=True)
        write_pcap(output)
        self.assertEqual(output.read_bytes(), CAPTURE.read_bytes())

    def test_invalid_magic_is_rejected(self) -> None:
        path = ROOT / "reports" / ".test-invalid.pcap"
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_bytes(b"not a pcap" + b"\x00" * 20)
        with self.assertRaises(PcapError):
            read_pcap(path)

    def test_truncated_record_is_rejected(self) -> None:
        path = ROOT / "reports" / ".test-truncated.pcap"
        self.addCleanup(path.unlink, missing_ok=True)
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        path.write_bytes(header + struct.pack("<IIII", 1, 0, 100, 100) + b"tiny")
        with self.assertRaises(PcapError):
            read_pcap(path)

    def test_cli_writes_report(self) -> None:
        output = ROOT / "reports" / ".test-report.md"
        self.addCleanup(output.unlink, missing_ok=True)
        with redirect_stdout(io.StringIO()):
            code = main([str(CAPTURE), "--output", str(output)])
        self.assertEqual(code, 0)
        self.assertIn("Incident severity: **CRITICAL**", output.read_text(encoding="utf-8"))

    def test_cli_json_output(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = main([str(CAPTURE), "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue())["packet_count"], 14)

    def test_cli_incident_gate_fails_for_findings(self) -> None:
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(CAPTURE), "--fail-on-incident"]), 1)


if __name__ == "__main__":
    unittest.main()
