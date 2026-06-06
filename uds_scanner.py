"""
UDS Diagnostic Scanner
======================
Simulates a UDS (ISO 14229) diagnostic session with an ECU.
Supports common services: Session Control, ECU Reset, Read DTC,
Read Data By Identifier, and Security Access handshake.

Author: Anurag Thaliyil Veedu
"""

import time
import random
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)


# ─── UDS Service IDs ──────────────────────────────────────────────────────────

class SID(IntEnum):
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET                  = 0x11
    SECURITY_ACCESS            = 0x27
    READ_DATA_BY_ID            = 0x22
    READ_DTC_INFO              = 0x19
    CLEAR_DTC                  = 0x14
    WRITE_DATA_BY_ID           = 0x2E
    COMMUNICATION_CONTROL      = 0x28


class SessionType(IntEnum):
    DEFAULT    = 0x01
    PROGRAMMING = 0x02
    EXTENDED   = 0x03


class NRC(IntEnum):
    """Negative Response Codes"""
    GENERAL_REJECT               = 0x10
    SERVICE_NOT_SUPPORTED        = 0x11
    SUB_FUNCTION_NOT_SUPPORTED   = 0x12
    INCORRECT_MESSAGE_LENGTH     = 0x13
    CONDITIONS_NOT_CORRECT       = 0x22
    REQUEST_OUT_OF_RANGE         = 0x31
    SECURITY_ACCESS_DENIED       = 0x33
    INVALID_KEY                  = 0x35
    EXCEEDED_NUMBER_OF_ATTEMPTS  = 0x36
    RESPONSE_PENDING             = 0x78


class DTCSeverity(IntEnum):
    LOW      = 0x20
    MEDIUM   = 0x40
    HIGH     = 0x60
    CRITICAL = 0x80


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class DTC:
    code: str
    description: str
    severity: DTCSeverity
    status: int  # DTC status byte per ISO 14229

    def is_active(self) -> bool:
        return bool(self.status & 0x01)

    def __str__(self):
        active = "ACTIVE" if self.is_active() else "STORED"
        return f"{self.code} [{DTCSeverity(self.severity).name}] {self.description} ({active})"


@dataclass
class ECUResponse:
    service_id: int
    data: bytes
    success: bool
    nrc: Optional[int] = None
    timestamp: float = field(default_factory=time.time)

    def __str__(self):
        if self.success:
            return f"[OK] SID=0x{self.service_id:02X}  Data={self.data.hex(' ').upper()}"
        return f"[NRC] SID=0x{self.service_id:02X}  Code=0x{self.nrc:02X} ({NRC(self.nrc).name})"


# ─── Simulated ECU ────────────────────────────────────────────────────────────

class SimulatedECU:
    """
    Simulates a minimal UDS-compliant ECU (e.g. EPS or Display controller).
    Responds to key diagnostic services with realistic latency and occasional
    negative responses to mirror real-world behavior.
    """

    DID_MAP = {
        0xF190: ("VIN",              b"WDB2030041A123456"),
        0xF18C: ("ECU Serial No.",   b"ECU_SN_0042"),
        0xF187: ("Part Number",      b"A2229007803"),
        0xF180: ("Boot SW Version",  b"BT_01.04.00"),
        0xF181: ("App SW Version",   b"AP_02.11.03"),
        0xF186: ("Active Session",   None),   # dynamic
        0x2000: ("Steering Torque",  None),   # dynamic
        0x2001: ("Motor Temperature", None),  # dynamic
    }

    SEED_KEY_PAIRS = {
        0xA1B2: 0x5C6D,   # seed → expected key (simplified)
        0xC3D4: 0x7E8F,
    }

    def __init__(self, ecu_name: str = "EPS_ECU"):
        self.name = ecu_name
        self.session = SessionType.DEFAULT
        self.security_unlocked = False
        self._pending_seed: Optional[int] = None
        self._fault_injection = False  # toggle to simulate ECU faults

        self.dtcs: list[DTC] = [
            DTC("C0044-00", "Steering Angle Sensor Signal Implausible", DTCSeverity.HIGH,   0x09),
            DTC("C0050-00", "EPS Motor Current Overload",               DTCSeverity.CRITICAL, 0x01),
            DTC("U0100-00", "Lost Communication with ECM",              DTCSeverity.MEDIUM,  0x08),
        ]

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _latency(self):
        """Simulate realistic ECU response latency (10–80 ms)."""
        time.sleep(random.uniform(0.01, 0.08))

    def _negative_response(self, sid: int, nrc: int) -> ECUResponse:
        self._latency()
        return ECUResponse(service_id=sid, data=bytes([0x7F, sid, nrc]),
                           success=False, nrc=nrc)

    def _positive_response(self, sid: int, payload: bytes) -> ECUResponse:
        self._latency()
        return ECUResponse(service_id=sid, data=bytes([sid + 0x40]) + payload, success=True)

    # ── UDS Services ─────────────────────────────────────────────────────────

    def diagnostic_session_control(self, session_type: SessionType) -> ECUResponse:
        if session_type == SessionType.PROGRAMMING and not self.security_unlocked:
            return self._negative_response(SID.DIAGNOSTIC_SESSION_CONTROL,
                                           NRC.CONDITIONS_NOT_CORRECT)
        self.session = session_type
        log.debug(f"{self.name}: Session changed to {session_type.name}")
        return self._positive_response(SID.DIAGNOSTIC_SESSION_CONTROL,
                                       bytes([session_type, 0x00, 0x19, 0x01]))

    def ecu_reset(self, reset_type: int = 0x01) -> ECUResponse:
        self.session = SessionType.DEFAULT
        self.security_unlocked = False
        log.debug(f"{self.name}: ECU reset (type=0x{reset_type:02X})")
        return self._positive_response(SID.ECU_RESET, bytes([reset_type]))

    def security_access(self, sub_func: int, data: bytes = b"") -> ECUResponse:
        if sub_func % 2 == 1:  # Request seed
            seed = random.choice(list(self.SEED_KEY_PAIRS.keys()))
            self._pending_seed = seed
            return self._positive_response(SID.SECURITY_ACCESS,
                                           bytes([sub_func + 1,
                                                  (seed >> 8) & 0xFF, seed & 0xFF]))
        else:  # Send key
            if not self._pending_seed:
                return self._negative_response(SID.SECURITY_ACCESS, NRC.CONDITIONS_NOT_CORRECT)
            supplied_key = int.from_bytes(data, "big")
            expected_key = self.SEED_KEY_PAIRS.get(self._pending_seed, 0)
            if supplied_key == expected_key:
                self.security_unlocked = True
                self._pending_seed = None
                return self._positive_response(SID.SECURITY_ACCESS, bytes([sub_func]))
            else:
                return self._negative_response(SID.SECURITY_ACCESS, NRC.INVALID_KEY)

    def read_data_by_id(self, did: int) -> ECUResponse:
        if did not in self.DID_MAP:
            return self._negative_response(SID.READ_DATA_BY_ID, NRC.REQUEST_OUT_OF_RANGE)

        label, static_data = self.DID_MAP[did]

        if did == 0xF186:
            data = bytes([self.session])
        elif did == 0x2000:
            torque = random.randint(-500, 500)   # -50.0 to +50.0 Nm (x0.1)
            data = torque.to_bytes(2, "big", signed=True)
        elif did == 0x2001:
            temp = random.randint(200, 1200)     # 20.0 to 120.0 °C (x0.1)
            data = temp.to_bytes(2, "big")
        else:
            data = static_data

        return self._positive_response(SID.READ_DATA_BY_ID,
                                       bytes([(did >> 8) & 0xFF, did & 0xFF]) + data)

    def read_dtc(self, sub_func: int = 0x02) -> ECUResponse:
        """sub_func 0x02 = reportDTCByStatusMask (all)"""
        payload = bytes([sub_func, 0xFF])   # status availability mask
        for dtc in self.dtcs:
            code_bytes = int(dtc.code.replace("-", "").replace("C", "C0").split("-")[0], 16)
            payload += bytes([(code_bytes >> 16) & 0xFF,
                               (code_bytes >> 8) & 0xFF,
                               code_bytes & 0xFF,
                               dtc.status])
        return self._positive_response(SID.READ_DTC_INFO, payload)

    def clear_dtc(self) -> ECUResponse:
        if self.session == SessionType.DEFAULT:
            return self._negative_response(SID.CLEAR_DTC, NRC.CONDITIONS_NOT_CORRECT)
        for dtc in self.dtcs:
            dtc.status &= ~0x01   # clear testFailed bit
        return self._positive_response(SID.CLEAR_DTC, b"")


# ─── Diagnostic Tester ────────────────────────────────────────────────────────

class UDSTester:
    """High-level diagnostic tester that orchestrates a full scan session."""

    def __init__(self, ecu: SimulatedECU):
        self.ecu = ecu
        self.results: list[str] = []

    def _log(self, msg: str):
        log.info(msg)
        self.results.append(msg)

    def run_full_scan(self):
        self._log("=" * 60)
        self._log(f"  UDS Diagnostic Scan — Target: {self.ecu.name}")
        self._log("=" * 60)

        # 1. Open extended session
        self._log("\n[1] Opening Extended Diagnostic Session...")
        resp = self.ecu.diagnostic_session_control(SessionType.EXTENDED)
        self._log(f"    {resp}")

        # 2. Read static identifiers
        self._log("\n[2] Reading ECU Identifiers...")
        for did in [0xF190, 0xF187, 0xF180, 0xF181]:
            resp = self.ecu.read_data_by_id(did)
            label = self.ecu.DID_MAP[did][0]
            if resp.success:
                value = resp.data[3:].decode(errors="replace")
                self._log(f"    {label:<20} : {value}")
            else:
                self._log(f"    {label:<20} : {resp}")

        # 3. Security access
        self._log("\n[3] Security Access Handshake (Level 0x01)...")
        seed_resp = self.ecu.security_access(0x01)
        self._log(f"    Seed response  : {seed_resp}")
        if seed_resp.success:
            seed = int.from_bytes(seed_resp.data[2:4], "big")
            key = self.ecu.SEED_KEY_PAIRS.get(seed, 0xFFFF)
            key_resp = self.ecu.security_access(0x02, key.to_bytes(2, "big"))
            self._log(f"    Key response   : {key_resp}")

        # 4. Read live data
        self._log("\n[4] Reading Live Data...")
        for did, label in [(0x2000, "Steering Torque (x0.1 Nm)"),
                            (0x2001, "Motor Temp (x0.1 °C)"),
                            (0xF186, "Active Session")]:
            resp = self.ecu.read_data_by_id(did)
            if resp.success:
                raw = resp.data[3:]
                self._log(f"    {label:<30} : 0x{raw.hex().upper()} ({int.from_bytes(raw, 'big', signed=(did==0x2000))})")

        # 5. Read DTCs
        self._log("\n[5] Reading Fault Memory (DTCs)...")
        for dtc in self.ecu.dtcs:
            self._log(f"    {dtc}")

        # 6. Attempt clear DTC in extended session
        self._log("\n[6] Clearing DTCs (Extended Session)...")
        resp = self.ecu.clear_dtc()
        self._log(f"    {resp}")

        # 7. ECU reset
        self._log("\n[7] Performing Soft Reset...")
        resp = self.ecu.ecu_reset(0x01)
        self._log(f"    {resp}")

        self._log("\n" + "=" * 60)
        self._log("  Scan complete.")
        self._log("=" * 60)

    def export_report(self, path: str = "scan_report.txt"):
        with open(path, "w") as f:
            f.write("\n".join(self.results))
        log.info(f"Report saved to {path}")


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ecu = SimulatedECU("EPS_ECU_SN0042")
    tester = UDSTester(ecu)
    tester.run_full_scan()
    tester.export_report("scan_report.txt")
