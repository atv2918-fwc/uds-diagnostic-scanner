# UDS Diagnostic Scanner 🔌

A Python simulation of a **UDS (ISO 14229) diagnostic tester** interacting with an automotive ECU — modelled on real-world diagnostics work with Electric Power Steering and Display controllers 

## Features

- Full UDS session lifecycle: Default → Extended → Programming
- Services implemented: `0x10` Session Control, `0x11` ECU Reset, `0x22` Read Data By ID, `0x19` Read DTC, `0x14` Clear DTC, `0x27` Security Access
- Seed-key security access handshake (simplified algorithm)
- Realistic ECU negative response codes (NRC) per ISO 14229
- Simulated DTC fault memory with status byte decoding
- Live data simulation (steering torque, motor temperature)
- Auto-export scan report to `.txt`

## Project Structure

```
uds-diagnostic-scanner/
├── uds_scanner.py      # Core scanner + simulated ECU
├── tests/
│   └── test_scanner.py # Unit tests for UDS services
└── README.md
```

## Quick Start

```bash
pip install -r requirements.txt
python uds_scanner.py
```

Sample output:
```
============================================================
  UDS Diagnostic Scan — Target: EPS_ECU_SN0042
============================================================

[1] Opening Extended Diagnostic Session...
    [OK] SID=0x10  Data=50 03 00 19 01

[2] Reading ECU Identifiers...
    VIN                  : WDB2030041A123456
    Part Number          : A2229007803
    Boot SW Version      : BT_01.04.00
    App SW Version       : AP_02.11.03

[5] Reading Fault Memory (DTCs)...
    C0044-00 [HIGH] Steering Angle Sensor Signal Implausible (ACTIVE)
    C0050-00 [CRITICAL] EPS Motor Current Overload (ACTIVE)
    U0100-00 [MEDIUM] Lost Communication with ECM (STORED)
```

## Background

This project mirrors the kind of diagnostic tooling I built at **Mercedes-Benz R&D India** — where I developed and maintained software test modules for EPS, Display, and Sound System ECUs, managed full release lifecycles to plants in Germany and China, and resolved safety-critical issues through UDS-based root cause analysis.

## Standards Referenced

- ISO 14229-1 (UDS)
- ISO 15031-6 (DTC format)
- ISO 15765-2 (CAN transport layer — TP layer not simulated here)
