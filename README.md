# ProShield – SOC Threat Detection System

## Overview

ProShield is a SOC-focused threat detection project designed to identify suspicious authentication activity from Linux logs.

It simulates how a Security Operations Center (SOC) detects early-stage attacks using log analysis and rule-based detection.

---

## Detection Focus

### Brute Force Detection (MITRE ATT&CK T1110)

- Source: Linux auth.log
- Analyzes failed login attempts
- Detects high-frequency authentication failures from the same source

### Detection Logic

If multiple failed login attempts occur within a short time window → flag as suspicious (possible brute-force attack)

---

## How It Works

1. Reads authentication events from auth.log
2. Filters failed login attempts
3. Groups events based on frequency and timing
4. Identifies abnormal patterns
5. Generates alert for suspicious activity

---

## Example Detection Output

[ALERT] Potential Brute-Force Attack Detected  
Source IP: 192.168.1.10  
Failed Attempts: 15 in 2 minutes  
Mapped Technique: MITRE ATT&CK T1110  

---

## Technologies Used

- Python (for detection logic)
- Wazuh (SIEM concepts)
- MITRE ATT&CK Framework
- Wireshark (network analysis basics)

---

## Key Concepts Demonstrated

- Log-based threat detection  
- Authentication log analysis (auth.log)  
- Alert generation based on event patterns  
- Basic SOC investigation workflow  
- MITRE ATT&CK mapping  

---

## Limitations

- Rule-based detection (no advanced analytics)  
- Simulated environment (no enterprise log pipeline)  
- Limited attack coverage (focused on brute-force)  

---

## Future Improvements

- Real-time log ingestion  
- Detection for additional attack types (DNS anomalies, lateral movement)  
- Enhanced MITRE mapping  
- SOC-style dashboard for monitoring  

---

## Summary

ProShield demonstrates how authentication logs can be analyzed to detect brute-force attacks and generate alerts using SOC-style detection logic.
