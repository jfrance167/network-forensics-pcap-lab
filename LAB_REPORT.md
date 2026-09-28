# Network Forensics and PCAP Investigation Report

## Research question

Can a deterministic packet-analysis workflow identify and correlate multiple stages of a simulated network intrusion from raw PCAP evidence?

## Hypothesis

Parsing DNS, HTTP, connection timing, and outbound payload volume will reconstruct the incident and distinguish isolated observations from a coordinated attack chain.

## Evidence and controls

- **Evidence:** a synthetic Ethernet/IPv4 PCAP containing 14 packets.
- **Independent variable:** packet behavior and timing.
- **Dependent variables:** detection rule, evidence, severity, indicators, and incident rating.
- **Controls:** RFC 1918 internal addressing, documentation-only external addressing, `.example` domains, fixed timestamps, and repeatable packet order.

## Procedure

1. Generate the evidence capture from reviewed source code.
2. Validate the PCAP global header and each record length.
3. Decode Ethernet, IPv4, TCP, UDP, DNS queries, and HTTP requests.
4. Identify suspicious DNS, executable-like downloads, cleartext authorization, periodic beacons, and outbound transfer bursts.
5. Correlate findings into a timeline and extract indicators.
6. Validate detections with positive, negative, malformed-input, and reproducibility tests.

## Results

The investigation parsed all 14 packets and produced five findings:

| Rule | Observation | MITRE ATT&CK |
|---|---|---|
| NET-001 | Suspicious DNS query | T1071.004 |
| NET-002 | Executable-like HTTP download | T1105 |
| NET-003 | Cleartext Basic authorization | T1557 |
| NET-004 | Five check-ins at 60-second intervals | T1071.001 |
| NET-005 | 5,200 outbound payload bytes in ten seconds | T1041 |

The correlated incident severity was critical. The affected internal host was `10.10.20.15`; every external address came from an IANA documentation range and every domain ended in `.example`.

## Analysis

No single observation proves compromise on its own. The ordered combination of infrastructure resolution, payload retrieval, regular application-layer beaconing, and concentrated outbound transfer provides substantially stronger evidence. The workflow retains timestamps and concise evidence so an analyst can pivot into endpoint, DNS, proxy, authentication, and firewall logs.

## Limitations

This parser intentionally supports classic Ethernet PCAP with IPv4 TCP/UDP. It does not implement PCAPNG, IPv6, IP fragmentation, TCP stream reassembly, TLS decryption, DNS compression, retransmission handling, or capture-loss analysis. Production investigations should use maintained tools such as Wireshark, Zeek, Suricata, or NetworkMiner and preserve chain of custody.

## Conclusion

The hypothesis was supported. Multi-signal correlation reconstructed the complete simulated incident, while negative tests prevented short beacon sequences and subthreshold transfers from triggering their corresponding rules.
