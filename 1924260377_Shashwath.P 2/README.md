# Network Security and Firewall Monitoring System

**Student:** Shashwath P  
**Register Number:** 1924260377  
**Project:** Network Security and Firewall Monitoring System

## Overview
A Python/Tkinter educational firewall-monitoring simulator. It accepts traffic details,
checks configurable firewall rules using source IP, destination IP, port and protocol,
classifies traffic as Allowed or Blocked, raises an alert for blocked attempts, maintains
a text log, displays dashboard counts and exports events as CSV.

## Requirements
- Python 3.9 or later
- Tkinter (usually included with standard Python installations)

No third-party Python packages are required.

## Run
```bash
python3 network_security_firewall.py
```

On Windows:
```bash
py network_security_firewall.py
```

## How to use
1. Run the program.
2. Enter source IP, destination IP, port, protocol and traffic direction.
3. Click **Inspect traffic**.
4. Add or edit the firewall rule list in the program as required. The GUI also supports
   adding rules while the program is running.
5. Click **Load demonstration traffic** to test the sample cases.
6. Use **Export log as CSV** to save the displayed event records.

## Default rules and expected demo result
Three sample rules permit TCP/80 from 192.168.1.10, TCP/443 from 192.168.1.20,
and UDP/53 from 192.168.1.30 to 192.168.1.100. Unmatched traffic is blocked.
The five demonstration records should result in 3 Allowed and 2 Blocked events.

## Files
- `network_security_firewall.py` — application source code
- `README.md` — project instructions
- `requirements.txt` — dependency note
- `sample_security_log.txt` — illustrative sample output
- `REPORT_1924260377_Shashwath.P.pdf` — project report

## Important scope and safety note
This project simulates firewall decisions on records entered by the user. It does not
capture live network packets, enforce rules on a real network interface, or change the
computer's operating-system firewall. The sample addresses are private documentation
addresses for demonstration. A production deployment would require authorized packet
capture, OS firewall integration, authentication, secure log storage, and testing.
