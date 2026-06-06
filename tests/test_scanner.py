"""Unit tests for UDS Diagnostic Scanner."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from uds_scanner import SimulatedECU, SessionType, NRC, SID, UDSTester


@pytest.fixture
def ecu():
    return SimulatedECU("TEST_ECU")


def test_default_session_open(ecu):
    resp = ecu.diagnostic_session_control(SessionType.DEFAULT)
    assert resp.success
    assert ecu.session == SessionType.DEFAULT


def test_extended_session_open(ecu):
    resp = ecu.diagnostic_session_control(SessionType.EXTENDED)
    assert resp.success
    assert ecu.session == SessionType.EXTENDED


def test_programming_session_requires_security(ecu):
    resp = ecu.diagnostic_session_control(SessionType.PROGRAMMING)
    assert not resp.success
    assert resp.nrc == NRC.CONDITIONS_NOT_CORRECT


def test_security_access_valid_key(ecu):
    seed_resp = ecu.security_access(0x01)
    assert seed_resp.success
    seed = int.from_bytes(seed_resp.data[2:4], "big")
    key = ecu.SEED_KEY_PAIRS.get(seed, 0x0000)
    key_resp = ecu.security_access(0x02, key.to_bytes(2, "big"))
    assert key_resp.success
    assert ecu.security_unlocked


def test_security_access_invalid_key(ecu):
    ecu.security_access(0x01)  # get seed
    bad_key_resp = ecu.security_access(0x02, b"\xFF\xFF")
    assert not bad_key_resp.success
    assert bad_key_resp.nrc == NRC.INVALID_KEY
    assert not ecu.security_unlocked


def test_read_vin(ecu):
    resp = ecu.read_data_by_id(0xF190)
    assert resp.success
    assert b"WDB" in resp.data


def test_read_unknown_did(ecu):
    resp = ecu.read_data_by_id(0x9999)
    assert not resp.success
    assert resp.nrc == NRC.REQUEST_OUT_OF_RANGE


def test_read_dtc_returns_all(ecu):
    resp = ecu.read_dtc()
    assert resp.success
    # 3 DTCs * 4 bytes each + 2 byte header = at least 14 bytes in payload
    assert len(resp.data) >= 14


def test_clear_dtc_in_default_session_fails(ecu):
    resp = ecu.clear_dtc()
    assert not resp.success
    assert resp.nrc == NRC.CONDITIONS_NOT_CORRECT


def test_clear_dtc_in_extended_session_succeeds(ecu):
    ecu.diagnostic_session_control(SessionType.EXTENDED)
    resp = ecu.clear_dtc()
    assert resp.success
    for dtc in ecu.dtcs:
        assert not dtc.is_active()


def test_ecu_reset_closes_session(ecu):
    ecu.diagnostic_session_control(SessionType.EXTENDED)
    ecu.ecu_reset()
    assert ecu.session == SessionType.DEFAULT
    assert not ecu.security_unlocked


def test_full_scan_runs_without_error(ecu):
    tester = UDSTester(ecu)
    tester.run_full_scan()
    assert len(tester.results) > 10
