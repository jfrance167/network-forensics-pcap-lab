# Network Forensics Investigation Report

- Evidence: `synthetic-incident.pcap`
- Packets analyzed: **14**
- Incident severity: **CRITICAL**
- Findings: **5**

## Timeline

| Time (UTC) | Rule | Severity | Source | Destination | Finding | Evidence |
|---|---|---|---|---|---|---|
| 2026-09-28T14:00:05+00:00 | NET-001 | high | 10.10.20.15 | 192.0.2.53 | Suspicious DNS lookup | query=cdn-sync.example |
| 2026-09-28T14:00:07+00:00 | NET-002 | high | 10.10.20.15 | 203.0.113.50 | Executable-like HTTP download | request=GET /download/loader.bin; host=cdn-sync.example |
| 2026-09-28T14:00:10+00:00 | NET-003 | medium | 10.10.20.15 | 198.51.100.10 | Cleartext Basic authorization observed | request=GET /profile; credential-value=redacted |
| 2026-09-28T14:00:20+00:00 | NET-004 | critical | 10.10.20.15 | 203.0.113.50 | Periodic command-and-control beacon | destination_port=8080; checkins=5; interval_seconds=60 |
| 2026-09-28T14:05:00+00:00 | NET-005 | high | 10.10.20.15 | 203.0.113.77 | High-volume outbound transfer | payload_bytes=5200; window_seconds=10 |

## Indicators

- Internal hosts: 10.10.20.15
- External hosts: 192.0.2.53, 198.51.100.10, 203.0.113.50, 203.0.113.77
- Queried domains: cdn-sync.example, portal.example

## Recommended Response

1. Isolate the affected workstation while preserving volatile evidence.
2. Block confirmed malicious destinations and domains after validation.
3. Acquire endpoint telemetry and correlate process, DNS, and proxy events.
4. Reset exposed credentials and prohibit cleartext authentication.
5. Scope for other hosts exhibiting the same beacon interval or indicators.
