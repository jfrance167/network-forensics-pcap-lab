# Network Forensics PCAP Investigation Lab

A defensive blue-team lab that generates and analyzes a real, deterministic PCAP using only Python's standard library. All IP addresses use private or documentation-only ranges, all domains use `.example`, and no malicious software or live attack traffic is included.

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

## Safe-use boundary

Analyze only captures you own or are explicitly authorized to inspect. Packet captures may contain credentials and personal information; sanitize evidence before sharing it.
