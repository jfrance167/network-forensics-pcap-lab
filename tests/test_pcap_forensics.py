import io
import json
import struct
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from generate_synthetic_pcap import build_packets, dns_query, write_pcap
from pcap_forensics import (
    PcapError,
    analyze,
    dns_query_name,
    http_request,
    main,
    read_pcap,
    render_markdown,
)


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "samples" / "synthetic-incident.pcap"


class PcapForensicsTests(unittest.TestCase):
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

    def test_report_contains_timeline(self) -> None:
        report = render_markdown(analyze(read_pcap(CAPTURE)), "sample|capture.pcap")
        self.assertIn("## Timeline", report)
        self.assertIn("NET-004", report)

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
