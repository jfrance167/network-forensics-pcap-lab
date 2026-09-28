# Incident Response Playbook

## Validate

Confirm timestamps, sensor placement, capture completeness, affected host ownership, and whether the detected destinations are expected business infrastructure. Preserve the original capture read-only and record its cryptographic hash in the case system.

## Contain

1. Isolate the affected endpoint without powering it off when volatile evidence is required.
2. Block validated malicious domains, addresses, and destination ports at appropriate controls.
3. Disable or reset credentials exposed through cleartext protocols.
4. Hunt for matching indicators and 60-second check-in behavior across other systems.

## Investigate

Correlate the timeline with EDR process trees, DNS resolver logs, proxy transactions, firewall sessions, identity events, email telemetry, and file hashes. Determine initial access, execution, persistence, credential exposure, lateral movement, and data-access scope.

## Eradicate and recover

Remove confirmed persistence, patch the entry point, rotate affected secrets, restore from validated sources, and monitor the recovered host. Do not rely solely on blocking the indicators from this capture.

## Lessons learned

Document detection gaps, containment timing, affected assets, root cause, and preventive actions. Convert validated indicators and behaviors into governed detections with owners and review dates.
