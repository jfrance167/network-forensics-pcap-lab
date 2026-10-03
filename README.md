# Network Forensics PCAP Investigation Lab

A defensive blue-team lab that generates and analyzes a real, deterministic PCAP using only Python's standard library. The analyzer caps input at 64 MiB, each captured record at 1 MiB, and the number of records at 100,000. All IP addresses use private or documentation-only ranges, all domains use `.example`, and no malicious software or live attack traffic is included.

## Investigation scenario

A fictional workstation exhibits a suspicious DNS lookup, executable-like HTTP download, cleartext authentication, periodic command-and-control-style check-ins, and a burst of outbound data. The analyst must reconstruct the timeline, extract indicators, map behavior to MITRE ATT&CK, and recommend containment actions.

## Run the lab

Rebuild the evidence file:

```bash
python generate_synthetic_pcap.py samples/synthetic-incident.pcap
```

Analyze it and generate the report:

```bash
python pcap_forensics.py samples/synthetic-incident.pcap \
  --output reports/network-forensics-report.md
```

Run verification:

```bash
python -m unittest discover -s tests -v
python -m bandit -q -r pcap_forensics.py generate_synthetic_pcap.py tests
```

## Expected result

The parser analyzes 14 packets and reports five findings with an overall `critical` incident rating. See the generated [investigation report](reports/network-forensics-report.md) and [formal lab report](LAB_REPORT.md).

## Detection detail limit

The summary retains at most one finding per rule ID. Inspect the underlying packet evidence for repeated affected endpoints or event instances; the summary is not a complete packet-by-packet timeline.

## Safe-use boundary

Analyze only captures you own or are explicitly authorized to inspect. Packet captures may contain credentials and personal information; sanitize evidence before sharing it.

Markdown reports treat capture-derived fields as untrusted text: control and format characters are normalized, Markdown control characters are escaped, and web addresses are defanged. JSON output keeps structured values unchanged for downstream processing.

## Repository map

```text
network-forensics-pcap-lab/
|-- .github/
|-- .gitignore
|-- INCIDENT_RESPONSE.md
|-- LAB_REPORT.md
|-- README.md
|-- SECURITY.md
|-- generate_synthetic_pcap.py
|-- pcap_forensics.py
|-- reports/
|-- samples/
`-- tests/
```

Follow the setup and safety boundaries above before running or deploying any code.
