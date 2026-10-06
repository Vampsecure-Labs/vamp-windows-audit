# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests unitarios para vamp-windows-audit."""

import json
import os
import tempfile

from vamp_windows_audit import (
    CHECKS,
    Finding,
    WinInfo,
    apply_delta,
    build_report,
    check_account_lockout,
    check_admin_renamed,
    check_audit_logon,
    check_auto_updates,
    check_defender,
    check_firewall,
    check_guest_account,
    check_laps,
    check_null_session_pipes,
    check_password_complexity,
    check_ps_policy,
    check_rdp_nla,
    check_remote_registry,
    check_smb_v1,
    check_uac,
    main,
    render_html,
    scan,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────

def secure() -> WinInfo:
    return WinInfo(
        hostname="SECURE-PC", os_version="Windows 11 Pro",
        smb_v1_enabled=False, guest_enabled=False,
        admin_renamed=True, admin_name="LocalAdmin",
        password_complexity=True, lockout_threshold=5,
        uac_enabled=True, uac_consent_admin=2,
        fw_domain_enabled=True, fw_private_enabled=True, fw_public_enabled=True,
        rdp_enabled=True, rdp_nla_required=True,
        defender_enabled=True, defender_rtp=True, defender_updated=True,
        auto_updates_enabled=True,
        audit_logon="Success and Failure",
        ps_execution_policy="RemoteSigned",
        remote_registry_running=False,
        laps_installed=True,
        null_session_pipes=[],
    )


def insecure() -> WinInfo:
    return WinInfo(
        hostname="INSECURE-PC", os_version="Windows 10 Home",
        smb_v1_enabled=True, guest_enabled=True,
        admin_renamed=False, admin_name="Administrator",
        password_complexity=False, lockout_threshold=0,
        uac_enabled=False, uac_consent_admin=0,
        fw_domain_enabled=False, fw_private_enabled=False, fw_public_enabled=False,
        rdp_enabled=True, rdp_nla_required=False,
        defender_enabled=False, defender_rtp=False, defender_updated=False,
        auto_updates_enabled=False,
        audit_logon="No Auditing",
        ps_execution_policy="Unrestricted",
        remote_registry_running=True,
        laps_installed=False,
        null_session_pipes=["LSARPC", "SAMR", "netlogon"],
    )


# ─── WIN-001: SMBv1 ───────────────────────────────────────────────────────────

def test_smb_v1_enabled():
    f = check_smb_v1(WinInfo(smb_v1_enabled=True))
    assert f is not None
    assert f.check_id == "WIN-001"
    assert f.severity == "critical"
    assert "SMBv1" in f.evidence[0]


def test_smb_v1_disabled():
    assert check_smb_v1(WinInfo(smb_v1_enabled=False)) is None


def test_smb_v1_unknown():
    assert check_smb_v1(WinInfo()) is None


# ─── WIN-002: Guest account ───────────────────────────────────────────────────

def test_guest_enabled():
    f = check_guest_account(WinInfo(guest_enabled=True))
    assert f is not None
    assert f.check_id == "WIN-002"
    assert f.severity == "high"


def test_guest_disabled():
    assert check_guest_account(WinInfo(guest_enabled=False)) is None


def test_guest_unknown():
    assert check_guest_account(WinInfo()) is None


# ─── WIN-003: Admin renamed ───────────────────────────────────────────────────

def test_admin_not_renamed():
    f = check_admin_renamed(WinInfo(admin_renamed=False, admin_name="Administrator"))
    assert f is not None
    assert f.check_id == "WIN-003"
    assert f.severity == "medium"
    assert "Administrator" in f.evidence[0]


def test_admin_renamed():
    assert check_admin_renamed(WinInfo(admin_renamed=True, admin_name="LocalAdmin")) is None


def test_admin_unknown():
    assert check_admin_renamed(WinInfo()) is None


# ─── WIN-004: Password complexity ────────────────────────────────────────────

def test_password_complexity_disabled():
    f = check_password_complexity(WinInfo(password_complexity=False))
    assert f is not None
    assert f.check_id == "WIN-004"
    assert f.severity == "high"


def test_password_complexity_enabled():
    assert check_password_complexity(WinInfo(password_complexity=True)) is None


def test_password_complexity_unknown():
    assert check_password_complexity(WinInfo()) is None


# ─── WIN-005: Account lockout ─────────────────────────────────────────────────

def test_account_lockout_zero():
    f = check_account_lockout(WinInfo(lockout_threshold=0))
    assert f is not None
    assert f.check_id == "WIN-005"
    assert f.severity == "high"


def test_account_lockout_set():
    assert check_account_lockout(WinInfo(lockout_threshold=5)) is None


def test_account_lockout_unknown():
    assert check_account_lockout(WinInfo()) is None


# ─── WIN-006: UAC ─────────────────────────────────────────────────────────────

def test_uac_disabled():
    f = check_uac(WinInfo(uac_enabled=False))
    assert f is not None
    assert f.check_id == "WIN-006"
    assert f.severity == "critical"


def test_uac_enabled():
    assert check_uac(WinInfo(uac_enabled=True)) is None


def test_uac_unknown():
    assert check_uac(WinInfo()) is None


# ─── WIN-007: Firewall ────────────────────────────────────────────────────────

def test_firewall_all_disabled():
    f = check_firewall(WinInfo(
        fw_domain_enabled=False, fw_private_enabled=False, fw_public_enabled=False))
    assert f is not None
    assert f.check_id == "WIN-007"
    assert f.severity == "high"
    assert len(f.evidence) == 3


def test_firewall_one_disabled():
    f = check_firewall(WinInfo(
        fw_domain_enabled=True, fw_private_enabled=True, fw_public_enabled=False))
    assert f is not None
    assert "Public" in f.evidence[0]


def test_firewall_all_enabled():
    assert check_firewall(WinInfo(
        fw_domain_enabled=True, fw_private_enabled=True, fw_public_enabled=True)) is None


def test_firewall_unknown():
    assert check_firewall(WinInfo()) is None


# ─── WIN-008: RDP NLA ─────────────────────────────────────────────────────────

def test_rdp_no_nla():
    f = check_rdp_nla(WinInfo(rdp_nla_required=False, rdp_enabled=True))
    assert f is not None
    assert f.check_id == "WIN-008"
    assert f.severity == "high"


def test_rdp_nla_ok():
    assert check_rdp_nla(WinInfo(rdp_nla_required=True, rdp_enabled=True)) is None


def test_rdp_disabled_no_finding():
    assert check_rdp_nla(WinInfo(rdp_nla_required=False, rdp_enabled=False)) is None


def test_rdp_unknown():
    assert check_rdp_nla(WinInfo()) is None


# ─── WIN-009: Defender ───────────────────────────────────────────────────────

def test_defender_av_disabled():
    f = check_defender(WinInfo(defender_enabled=False))
    assert f is not None
    assert f.check_id == "WIN-009"
    assert f.severity == "critical"
    assert "AntivirusEnabled" in f.evidence[0]


def test_defender_rtp_disabled():
    f = check_defender(WinInfo(defender_enabled=True, defender_rtp=False))
    assert f is not None
    assert f.check_id == "WIN-009"
    assert "RealTimeProtection" in f.evidence[0]


def test_defender_enabled():
    assert check_defender(WinInfo(defender_enabled=True, defender_rtp=True)) is None


def test_defender_unknown():
    assert check_defender(WinInfo()) is None


# ─── WIN-010: Auto updates ───────────────────────────────────────────────────

def test_auto_updates_disabled():
    f = check_auto_updates(WinInfo(auto_updates_enabled=False))
    assert f is not None
    assert f.check_id == "WIN-010"
    assert f.severity == "medium"


def test_auto_updates_enabled():
    assert check_auto_updates(WinInfo(auto_updates_enabled=True)) is None


def test_auto_updates_unknown():
    assert check_auto_updates(WinInfo()) is None


# ─── WIN-011: Audit logon ─────────────────────────────────────────────────────

def test_audit_no_auditing():
    f = check_audit_logon(WinInfo(audit_logon="No Auditing"))
    assert f is not None
    assert f.check_id == "WIN-011"
    assert f.severity == "medium"


def test_audit_success_failure():
    assert check_audit_logon(WinInfo(audit_logon="Success and Failure")) is None


def test_audit_success_only():
    assert check_audit_logon(WinInfo(audit_logon="Success")) is None


def test_audit_unknown():
    assert check_audit_logon(WinInfo()) is None


# ─── WIN-012: PowerShell policy ──────────────────────────────────────────────

def test_ps_unrestricted():
    f = check_ps_policy(WinInfo(ps_execution_policy="Unrestricted"))
    assert f is not None
    assert f.check_id == "WIN-012"
    assert f.severity == "medium"
    assert "Unrestricted" in f.evidence[0]


def test_ps_bypass():
    f = check_ps_policy(WinInfo(ps_execution_policy="Bypass"))
    assert f is not None
    assert "Bypass" in f.evidence[0]


def test_ps_remotesigned():
    assert check_ps_policy(WinInfo(ps_execution_policy="RemoteSigned")) is None


def test_ps_allsigned():
    assert check_ps_policy(WinInfo(ps_execution_policy="AllSigned")) is None


def test_ps_unknown():
    assert check_ps_policy(WinInfo()) is None


# ─── WIN-013: Remote Registry ────────────────────────────────────────────────

def test_remote_registry_running():
    f = check_remote_registry(WinInfo(remote_registry_running=True))
    assert f is not None
    assert f.check_id == "WIN-013"
    assert f.severity == "medium"


def test_remote_registry_stopped():
    assert check_remote_registry(WinInfo(remote_registry_running=False)) is None


def test_remote_registry_unknown():
    assert check_remote_registry(WinInfo()) is None


# ─── WIN-014: LAPS ───────────────────────────────────────────────────────────

def test_laps_not_installed():
    f = check_laps(WinInfo(laps_installed=False))
    assert f is not None
    assert f.check_id == "WIN-014"
    assert f.severity == "medium"


def test_laps_installed():
    assert check_laps(WinInfo(laps_installed=True)) is None


def test_laps_unknown():
    assert check_laps(WinInfo()) is None


# ─── WIN-015: Null session pipes ─────────────────────────────────────────────

def test_null_pipes_present():
    f = check_null_session_pipes(WinInfo(null_session_pipes=["LSARPC", "SAMR"]))
    assert f is not None
    assert f.check_id == "WIN-015"
    assert f.severity == "high"
    assert len(f.evidence) == 2


def test_null_pipes_empty():
    assert check_null_session_pipes(WinInfo(null_session_pipes=[])) is None


def test_null_pipes_whitespace_only():
    assert check_null_session_pipes(WinInfo(null_session_pipes=["", "  "])) is None


def test_null_pipes_unknown():
    assert check_null_session_pipes(WinInfo()) is None


# ─── Scan ─────────────────────────────────────────────────────────────────────

def test_scan_secure_zero_findings():
    assert scan(secure()) == []


def test_scan_insecure_all_15():
    findings = scan(insecure())
    assert len(findings) == 15
    assert {f.check_id for f in findings} == set(CHECKS.keys())


def test_scan_partial():
    info = WinInfo(smb_v1_enabled=True, uac_enabled=False, laps_installed=False)
    ids = {f.check_id for f in scan(info)}
    assert "WIN-001" in ids
    assert "WIN-006" in ids
    assert "WIN-014" in ids
    assert "WIN-002" not in ids


# ─── Finding.from_check ───────────────────────────────────────────────────────

def test_finding_from_check_all_ids():
    for cid in CHECKS:
        f = Finding.from_check(cid)
        assert f.check_id == cid
        assert f.severity in {"critical", "high", "medium", "low"}
        assert f.cis
        assert f.title


# ─── Report ──────────────────────────────────────────────────────────────────

def test_build_report_structure():
    info = WinInfo(hostname="TEST-PC", os_version="Windows 11")
    findings = [Finding.from_check("WIN-001"), Finding.from_check("WIN-010")]
    r = build_report(info, findings, "CASE-001", "Tester")
    assert r["summary"]["critical"] == 1
    assert r["summary"]["medium"] == 1
    assert r["summary"]["total"] == 2
    assert r["target"] == "TEST-PC"
    assert r["case"] == "CASE-001"


def test_render_html_finding():
    info = WinInfo(hostname="TARGET")
    findings = [Finding.from_check("WIN-001", evidence=["SMBv1: Enabled"])]
    report = build_report(info, findings)
    h = render_html(report)
    assert "WIN-001" in h
    assert "SMBv1" in h
    assert "CRITICAL" in h


def test_render_html_no_findings():
    h = render_html(build_report(WinInfo(hostname="OK"), []))
    assert "No se detectaron" in h


# ─── WinInfo helpers ──────────────────────────────────────────────────────────

def test_wininfo_from_dict_known_fields():
    d = {"hostname": "MYPC", "smb_v1_enabled": True, "unknown_key": "ignored"}
    w = WinInfo.from_dict(d)
    assert w.hostname == "MYPC"
    assert w.smb_v1_enabled is True


def test_wininfo_from_json_roundtrip():
    data = {"hostname": "JSONPC", "guest_enabled": True, "lockout_threshold": 0}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    try:
        w = WinInfo.from_json(path)
        assert w.hostname == "JSONPC"
        assert w.guest_enabled is True
        assert w.lockout_threshold == 0
    finally:
        os.unlink(path)


# ─── CLI exit codes ───────────────────────────────────────────────────────────

def test_exit_code_critical(tmp_path):
    data = {"hostname": "T", "smb_v1_enabled": True, "uac_enabled": False}
    f = tmp_path / "a.json"
    f.write_text(json.dumps(data))
    assert main(["--from-json", str(f), "--quiet"]) == 2


def test_exit_code_high_only(tmp_path):
    data = {"hostname": "T", "lockout_threshold": 0}
    f = tmp_path / "a.json"
    f.write_text(json.dumps(data))
    assert main(["--from-json", str(f), "--quiet"]) == 1


def test_exit_code_medium_only(tmp_path):
    data = {"hostname": "T", "auto_updates_enabled": False}
    f = tmp_path / "a.json"
    f.write_text(json.dumps(data))
    assert main(["--from-json", str(f), "--quiet"]) == 1


def test_exit_code_clean(tmp_path):
    f = tmp_path / "a.json"
    f.write_text(json.dumps({"hostname": "CLEAN"}))
    assert main(["--from-json", str(f), "--quiet"]) == 0


def test_collect_script_exit():
    assert main(["--collect-script"]) == 0


def test_invalid_json_path():
    assert main(["--from-json", "/nonexistent/file.json", "--quiet"]) == 3


def test_no_args_returns_3():
    assert main([]) == 3


# ─── v1.1.0 — apply_delta ────────────────────────────────────────────────────

def test_apply_delta_new(tmp_path):
    """Finding not in baseline → delta_state='new'."""
    baseline = {"findings": []}
    bf = tmp_path / "baseline.json"
    bf.write_text(json.dumps(baseline))
    findings = [Finding.from_check("WIN-001")]
    out, resolved = apply_delta(findings, str(bf))
    assert out[0].delta_state == "new"
    assert resolved == []


def test_apply_delta_recurring(tmp_path):
    """Finding also in baseline → delta_state='recurring'."""
    baseline = {"findings": [{"check_id": "WIN-001", "title": "t",
                               "severity": "critical", "category": "c",
                               "cis": "x", "description": "d", "evidence": []}]}
    bf = tmp_path / "baseline.json"
    bf.write_text(json.dumps(baseline))
    findings = [Finding.from_check("WIN-001")]
    out, resolved = apply_delta(findings, str(bf))
    assert out[0].delta_state == "recurring"
    assert resolved == []


def test_apply_delta_resolved(tmp_path):
    """Finding in baseline but not in current scan → appears in resolved."""
    old_f = {"check_id": "WIN-006", "title": "UAC", "severity": "critical",
              "category": "c", "cis": "x", "description": "d", "evidence": []}
    baseline = {"findings": [old_f]}
    bf = tmp_path / "baseline.json"
    bf.write_text(json.dumps(baseline))
    findings = []  # WIN-006 fixed
    out, resolved = apply_delta(findings, str(bf))
    assert out == []
    assert len(resolved) == 1
    assert resolved[0]["check_id"] == "WIN-006"


def test_apply_delta_bad_file():
    """Non-existent baseline raises ValueError."""
    import pytest
    with pytest.raises(ValueError, match="Cannot read baseline"):
        apply_delta([], "/nonexistent/baseline.json")


def test_build_report_with_resolved(tmp_path):
    """build_report includes delta section when resolved is passed."""
    info = WinInfo(hostname="T")
    findings = [Finding.from_check("WIN-001")]
    findings[0].delta_state = "new"
    resolved = [{"check_id": "WIN-006", "severity": "critical"}]
    r = build_report(info, findings, resolved=resolved)
    assert "delta" in r
    assert r["delta"]["new"] == 1
    assert r["delta"]["recurring"] == 0
    assert r["delta"]["resolved"][0]["check_id"] == "WIN-006"


def test_main_with_baseline(tmp_path):
    """main() with --baseline runs without error."""
    data = {"hostname": "T", "smb_v1_enabled": True}
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(data))
    baseline = {"findings": []}
    bl_file = tmp_path / "baseline.json"
    bl_file.write_text(json.dumps(baseline))
    code = main(["--from-json", str(scan_file), "--baseline", str(bl_file), "--quiet"])
    assert code == 2  # WIN-001 is critical
