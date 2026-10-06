# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp-windows-audit — Windows Security Configuration Auditor
15 CIS-aligned checks for common Windows security misconfigurations.
AGPL-3.0-only — for authorized security testing only.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

VERSION = "1.1.0"
TOOL = "vamp-windows-audit"

# ─── PowerShell collection script ─────────────────────────────────────────────

COLLECT_SCRIPT = r"""
# vamp-windows-audit collection script — run as Administrator on the target
# Output: JSON to stdout  |  vamp-windows-audit --collect-script | Set-Content collect.ps1

$info = @{}
$info['hostname'] = $env:COMPUTERNAME
try { $info['os_version'] = (Get-CimInstance Win32_OperatingSystem).Caption } catch {}

# SMBv1
try {
    $smb = Get-SmbServerConfiguration -EA Stop
    $info['smb_v1_enabled'] = [bool]$smb.EnableSMB1Protocol
} catch { $info['smb_v1_enabled'] = $null }

# Guest account
try {
    $g = Get-LocalUser -Name "Guest" -EA Stop
    $info['guest_enabled'] = [bool]$g.Enabled
} catch { $info['guest_enabled'] = $false }

# Administrator renamed (SID -500)
try {
    $a = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    $info['admin_renamed'] = ($a.Name -ne "Administrator")
    $info['admin_name']    = $a.Name
} catch { $info['admin_renamed'] = $null }

# Password policy
try {
    $n = net accounts 2>$null
    $info['password_complexity'] = (($n | Select-String "complexity") -match "Yes|1")
    $t = (($n | Select-String "lockout threshold") -replace "[^0-9]","").Trim()
    $info['lockout_threshold'] = if ($t) { [int]$t } else { 0 }
} catch {}

# UAC
try {
    $u = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA Stop
    $info['uac_enabled']        = ($u.EnableLUA -eq 1)
    $info['uac_consent_admin']  = [int]$u.ConsentPromptBehaviorAdmin
} catch { $info['uac_enabled'] = $null }

# Firewall
try {
    $fw = Get-NetFirewallProfile -EA Stop
    foreach ($p in $fw) { $info["fw_$($p.Name.ToLower())_enabled"] = [bool]$p.Enabled }
} catch {}

# RDP + NLA
try {
    $ts  = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA Stop
    $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -EA Stop
    $info['rdp_enabled']     = ($ts.fDenyTSConnections -eq 0)
    $info['rdp_nla_required']= ($rdp.UserAuthentication -eq 1)
} catch { $info['rdp_nla_required'] = $null }

# Windows Defender
try {
    $mp = Get-MpComputerStatus -EA Stop
    $info['defender_enabled'] = [bool]$mp.AntivirusEnabled
    $info['defender_rtp']     = [bool]$mp.RealTimeProtectionEnabled
    $info['defender_updated'] = ($mp.AntivirusSignatureAge -le 3)
} catch { $info['defender_enabled'] = $null }

# Auto-updates
try {
    $au = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -EA Stop
    $info['auto_updates_enabled'] = ($au.NoAutoUpdate -eq 0 -or $au.AUOptions -ge 3)
} catch { $info['auto_updates_enabled'] = $null }

# Audit policy — logon events
try {
    $ap = auditpol /get /subcategory:"Logon" /r 2>$null | ConvertFrom-Csv
    if ($ap) { $info['audit_logon'] = $ap.'Inclusion Setting' }
} catch {}

# PowerShell execution policy
try { $info['ps_execution_policy'] = (Get-ExecutionPolicy -Scope LocalMachine).ToString() } catch {}

# Remote Registry service
try {
    $r = Get-Service -Name RemoteRegistry -EA Stop
    $info['remote_registry_running'] = ($r.Status -eq "Running")
} catch { $info['remote_registry_running'] = $false }

# LAPS
try {
    $l1 = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA SilentlyContinue
    $l2 = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LAPS" -EA SilentlyContinue
    $l3 = Get-Module -ListAvailable -Name AdmPwd.PS -EA SilentlyContinue
    $info['laps_installed'] = ($null -ne $l1 -or $null -ne $l2 -or $null -ne $l3)
} catch { $info['laps_installed'] = $false }

# Null session pipes
try {
    $pipes = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -EA Stop).NullSessionPipes
    $info['null_session_pipes'] = if ($pipes) { @($pipes) } else { @() }
} catch { $info['null_session_pipes'] = $null }

$info | ConvertTo-Json -Depth 3 -Compress
"""

# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class WinInfo:
    hostname: Optional[str] = None
    os_version: Optional[str] = None
    smb_v1_enabled: Optional[bool] = None
    guest_enabled: Optional[bool] = None
    admin_renamed: Optional[bool] = None
    admin_name: Optional[str] = None
    password_complexity: Optional[bool] = None
    lockout_threshold: Optional[int] = None
    uac_enabled: Optional[bool] = None
    uac_consent_admin: Optional[int] = None
    fw_domain_enabled: Optional[bool] = None
    fw_private_enabled: Optional[bool] = None
    fw_public_enabled: Optional[bool] = None
    rdp_enabled: Optional[bool] = None
    rdp_nla_required: Optional[bool] = None
    defender_enabled: Optional[bool] = None
    defender_rtp: Optional[bool] = None
    defender_updated: Optional[bool] = None
    auto_updates_enabled: Optional[bool] = None
    audit_logon: Optional[str] = None
    ps_execution_policy: Optional[str] = None
    remote_registry_running: Optional[bool] = None
    laps_installed: Optional[bool] = None
    null_session_pipes: Optional[List[str]] = field(default=None)
    error: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "WinInfo":
        known = {k for k in d if k in cls.__dataclass_fields__}
        return cls(**{k: d[k] for k in known})

    @classmethod
    def from_json(cls, path: str) -> "WinInfo":
        with open(path) as fh:
            return cls.from_dict(json.load(fh))

    @classmethod
    def collect_local(cls) -> "WinInfo":
        if platform.system() != "Windows":
            return cls(error=(
                "La recogida de datos requiere Windows. "
                "Usa --collect-script para obtener el script PowerShell "
                "y ejecútalo en el equipo objetivo; luego analiza con --from-json."
            ))
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", COLLECT_SCRIPT],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return cls(error=f"Recogida fallida: {result.stderr[:200]}")
        try:
            return cls.from_dict(json.loads(result.stdout))
        except Exception as exc:
            return cls(error=f"JSON inválido: {exc}")


# ─── Check catalogue ──────────────────────────────────────────────────────────

CHECKS: Dict[str, dict] = {
    "WIN-001": {"title": "SMBv1 habilitado",
                "severity": "critical", "category": "Network Protocol",
                "cis": "CIS 18.3.3"},
    "WIN-002": {"title": "Cuenta Guest activa",
                "severity": "high", "category": "Account Management",
                "cis": "CIS 2.3.1.3"},
    "WIN-003": {"title": "Cuenta Administrator sin renombrar",
                "severity": "medium", "category": "Account Management",
                "cis": "CIS 2.3.1.1"},
    "WIN-004": {"title": "Complejidad de contraseña desactivada",
                "severity": "high", "category": "Password Policy",
                "cis": "CIS 1.1.5"},
    "WIN-005": {"title": "Umbral de bloqueo de cuenta no configurado",
                "severity": "high", "category": "Account Lockout",
                "cis": "CIS 1.2.2"},
    "WIN-006": {"title": "UAC desactivado",
                "severity": "critical", "category": "User Account Control",
                "cis": "CIS 2.3.17.1"},
    "WIN-007": {"title": "Windows Firewall desactivado (algún perfil)",
                "severity": "high", "category": "Firewall",
                "cis": "CIS 9.1-9.3"},
    "WIN-008": {"title": "RDP sin Network Level Authentication (NLA)",
                "severity": "high", "category": "Remote Desktop",
                "cis": "CIS 18.9.52.1"},
    "WIN-009": {"title": "Windows Defender / AV desactivado",
                "severity": "critical", "category": "Antivirus",
                "cis": "CIS 18.9.47.4"},
    "WIN-010": {"title": "Actualizaciones automáticas desactivadas",
                "severity": "medium", "category": "Patch Management",
                "cis": "CIS 18.9.8"},
    "WIN-011": {"title": "Auditoría de inicio de sesión no configurada",
                "severity": "medium", "category": "Audit Policy",
                "cis": "CIS 17.5.1"},
    "WIN-012": {"title": "PowerShell con política de ejecución irrestricta",
                "severity": "medium", "category": "PowerShell",
                "cis": "CIS 18.9.76.1"},
    "WIN-013": {"title": "Servicio Remote Registry activo",
                "severity": "medium", "category": "Services",
                "cis": "CIS 2.2.28"},
    "WIN-014": {"title": "LAPS no desplegado",
                "severity": "medium", "category": "Privileged Access",
                "cis": "CIS 2.3.1 (ext.)"},
    "WIN-015": {"title": "Null Session Pipes sin restringir",
                "severity": "high", "category": "Network Access",
                "cis": "CIS 2.3.10.3"},
}


# ─── Finding ──────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    category: str
    cis: str
    description: str
    evidence: List[str]
    delta_state: Optional[str] = None  # "new" | "recurring" when --baseline used

    def to_dict(self) -> dict:
        d = asdict(self)
        if d["delta_state"] is None:
            del d["delta_state"]
        return d

    @classmethod
    def from_check(cls, cid: str, description: str = "",
                   evidence: Optional[List[str]] = None) -> "Finding":
        m = CHECKS[cid]
        return cls(
            check_id=cid,
            title=m["title"],
            severity=m["severity"],
            category=m["category"],
            cis=m["cis"],
            description=description or m["title"],
            evidence=evidence or [],
        )


# ─── Pure check functions ─────────────────────────────────────────────────────

def check_smb_v1(info: WinInfo) -> Optional[Finding]:
    """WIN-001: SMBv1 — EternalBlue / WannaCry (MS17-010)."""
    if info.smb_v1_enabled is None:
        return None
    if info.smb_v1_enabled:
        return Finding.from_check(
            "WIN-001",
            "SMBv1 está habilitado. Vector crítico de WannaCry / EternalBlue (CVE-2017-0144).",
            ["SMBv1: Enabled"],
        )
    return None


def check_guest_account(info: WinInfo) -> Optional[Finding]:
    """WIN-002: Cuenta Guest activa."""
    if info.guest_enabled is None:
        return None
    if info.guest_enabled:
        return Finding.from_check(
            "WIN-002",
            "La cuenta Guest está habilitada. Permite acceso anónimo al sistema.",
            ["Guest account: Enabled"],
        )
    return None


def check_admin_renamed(info: WinInfo) -> Optional[Finding]:
    """WIN-003: Cuenta Administrator sin renombrar."""
    if info.admin_renamed is None:
        return None
    if not info.admin_renamed:
        name = info.admin_name or "Administrator"
        return Finding.from_check(
            "WIN-003",
            "La cuenta de administrador local usa el nombre predeterminado, "
            "facilitando ataques de fuerza bruta.",
            [f"Admin account name: {name}"],
        )
    return None


def check_password_complexity(info: WinInfo) -> Optional[Finding]:
    """WIN-004: Complejidad de contraseña desactivada."""
    if info.password_complexity is None:
        return None
    if not info.password_complexity:
        return Finding.from_check(
            "WIN-004",
            "La política de complejidad de contraseñas está desactivada.",
            ["Password complexity: Disabled"],
        )
    return None


def check_account_lockout(info: WinInfo) -> Optional[Finding]:
    """WIN-005: Sin umbral de bloqueo de cuenta."""
    if info.lockout_threshold is None:
        return None
    if info.lockout_threshold == 0:
        return Finding.from_check(
            "WIN-005",
            "El umbral de bloqueo es 0 (sin límite). "
            "Permite ataques de fuerza bruta ilimitados.",
            ["Lockout threshold: 0 (disabled)"],
        )
    return None


def check_uac(info: WinInfo) -> Optional[Finding]:
    """WIN-006: UAC desactivado."""
    if info.uac_enabled is None:
        return None
    if not info.uac_enabled:
        return Finding.from_check(
            "WIN-006",
            "UAC está desactivado. Cualquier proceso corre con privilegios de "
            "administrador sin confirmación.",
            ["EnableLUA: 0"],
        )
    return None


def check_firewall(info: WinInfo) -> Optional[Finding]:
    """WIN-007: Windows Firewall desactivado en algún perfil."""
    checks = {
        "Domain": info.fw_domain_enabled,
        "Private": info.fw_private_enabled,
        "Public": info.fw_public_enabled,
    }
    if all(v is None for v in checks.values()):
        return None
    disabled = [name for name, val in checks.items() if val is False]
    if disabled:
        return Finding.from_check(
            "WIN-007",
            f"Windows Firewall desactivado en los perfiles: {', '.join(disabled)}.",
            [f"Firewall disabled: {p}" for p in disabled],
        )
    return None


def check_rdp_nla(info: WinInfo) -> Optional[Finding]:
    """WIN-008: RDP sin NLA."""
    if info.rdp_nla_required is None:
        return None
    if info.rdp_enabled is False:
        return None
    if not info.rdp_nla_required:
        return Finding.from_check(
            "WIN-008",
            "RDP no exige Network Level Authentication (NLA). "
            "Permite iniciar la pantalla de login antes de autenticarse.",
            ["UserAuthentication: 0 (NLA not required)"],
        )
    return None


def check_defender(info: WinInfo) -> Optional[Finding]:
    """WIN-009: Windows Defender / AV desactivado o sin protección en tiempo real."""
    if info.defender_enabled is None:
        return None
    if not info.defender_enabled:
        return Finding.from_check(
            "WIN-009",
            "Windows Defender (antivirus) está desactivado. "
            "El sistema carece de protección contra malware.",
            ["AntivirusEnabled: False"],
        )
    if info.defender_rtp is False:
        return Finding.from_check(
            "WIN-009",
            "La protección en tiempo real de Windows Defender está desactivada.",
            ["RealTimeProtectionEnabled: False"],
        )
    return None


def check_auto_updates(info: WinInfo) -> Optional[Finding]:
    """WIN-010: Actualizaciones automáticas desactivadas."""
    if info.auto_updates_enabled is None:
        return None
    if not info.auto_updates_enabled:
        return Finding.from_check(
            "WIN-010",
            "Las actualizaciones automáticas están desactivadas o no configuradas. "
            "El sistema puede estar sin parches de seguridad.",
            ["AutoUpdate: Disabled"],
        )
    return None


def check_audit_logon(info: WinInfo) -> Optional[Finding]:
    """WIN-011: Auditoría de inicio de sesión sin configurar."""
    if info.audit_logon is None:
        return None
    policy = (info.audit_logon or "").lower()
    if "no auditing" in policy or policy.strip() == "":
        return Finding.from_check(
            "WIN-011",
            "Los eventos de inicio de sesión no se auditan. "
            "No hay trazabilidad de accesos al sistema.",
            [f"Logon audit: {info.audit_logon or 'No Auditing'}"],
        )
    return None


def check_ps_policy(info: WinInfo) -> Optional[Finding]:
    """WIN-012: PowerShell con política de ejecución irrestricta."""
    if info.ps_execution_policy is None:
        return None
    risky = {"Unrestricted", "Bypass"}
    policy = (info.ps_execution_policy or "").strip()
    if policy in risky:
        return Finding.from_check(
            "WIN-012",
            f"La política de ejecución de PowerShell es '{policy}'. "
            "Permite ejecutar scripts maliciosos sin restricción.",
            [f"ExecutionPolicy: {policy}"],
        )
    return None


def check_remote_registry(info: WinInfo) -> Optional[Finding]:
    """WIN-013: Servicio Remote Registry activo."""
    if info.remote_registry_running is None:
        return None
    if info.remote_registry_running:
        return Finding.from_check(
            "WIN-013",
            "El servicio Remote Registry está activo. "
            "Permite modificar el registro de Windows de forma remota.",
            ["RemoteRegistry: Running"],
        )
    return None


def check_laps(info: WinInfo) -> Optional[Finding]:
    """WIN-014: LAPS no desplegado."""
    if info.laps_installed is None:
        return None
    if not info.laps_installed:
        return Finding.from_check(
            "WIN-014",
            "LAPS (Local Administrator Password Solution) no está desplegado. "
            "La contraseña del administrador local puede ser idéntica en todos los equipos.",
            ["LAPS: Not installed"],
        )
    return None


def check_null_session_pipes(info: WinInfo) -> Optional[Finding]:
    """WIN-015: Null Session Pipes — acceso sin autenticación."""
    if info.null_session_pipes is None:
        return None
    pipes = [p.strip() for p in info.null_session_pipes if p.strip()]
    if pipes:
        return Finding.from_check(
            "WIN-015",
            f"{len(pipes)} named pipe(s) accesibles sin autenticación (null session). "
            "Permite enumeración de cuentas y datos del sistema.",
            [f"NullSessionPipe: {p}" for p in pipes[:5]],
        )
    return None


# ─── Scanner ──────────────────────────────────────────────────────────────────

_CHECKERS = [
    check_smb_v1, check_guest_account, check_admin_renamed,
    check_password_complexity, check_account_lockout, check_uac,
    check_firewall, check_rdp_nla, check_defender, check_auto_updates,
    check_audit_logon, check_ps_policy, check_remote_registry,
    check_laps, check_null_session_pipes,
]


def scan(info: WinInfo) -> List[Finding]:
    findings = []
    for fn in _CHECKERS:
        result = fn(info)
        if result:
            findings.append(result)
    return findings


# ─── Delta ────────────────────────────────────────────────────────────────────

def apply_delta(
    findings: List[Finding], baseline_path: str
) -> tuple:
    """Annotate findings as 'new'/'recurring'; return (annotated, resolved_list).

    resolved_list contains finding dicts from the baseline that are no longer
    present in the current scan — issues that were fixed.
    """
    try:
        baseline_data = json.loads(
            Path(baseline_path).read_text(encoding="utf-8")
        )
    except Exception as exc:
        raise ValueError(f"Cannot read baseline '{baseline_path}': {exc}") from exc

    baseline_ids = {f["check_id"] for f in baseline_data.get("findings", [])}
    current_ids = {f.check_id for f in findings}

    for f in findings:
        f.delta_state = "recurring" if f.check_id in baseline_ids else "new"

    resolved = [
        f for f in baseline_data.get("findings", [])
        if f["check_id"] not in current_ids
    ]
    return findings, resolved


# ─── Report ───────────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_report(info: WinInfo, findings: List[Finding],
                 case: str = "", analyst: str = "",
                 resolved: Optional[List[dict]] = None) -> dict:
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    report = {
        "tool": TOOL,
        "version": VERSION,
        "generated": datetime.now(timezone.utc).isoformat(),
        "target": info.hostname or "unknown",
        "os": info.os_version or "unknown",
        "case": case,
        "analyst": analyst,
        "summary": {**counts, "total": len(findings)},
        "findings": sorted(
            [f.to_dict() for f in findings],
            key=lambda x: _SEV_ORDER.get(x["severity"], 9),
        ),
    }
    if resolved is not None:
        report["delta"] = {
            "new": sum(1 for f in findings if f.delta_state == "new"),
            "recurring": sum(1 for f in findings if f.delta_state == "recurring"),
            "resolved": resolved,
        }
    return report


def render_html(report: dict) -> str:
    _SEV_COLOR = {
        "critical": "#c0392b", "high": "#e67e22",
        "medium": "#f39c12", "low": "#27ae60", "info": "#2980b9",
    }
    s = report["summary"]

    def badge(sev: str, c: int) -> str:
        return (f"<span class='badge' style='background:{_SEV_COLOR[sev]}'>"
                f"{c} {sev.upper()}</span>")

    _DELTA_STYLE = {
        "new": ("🆕 NEW", "#1f6feb", "#388bfd"),
        "recurring": ("🔁 RECURRING", "#6e3d1b", "#f0883e"),
    }

    findings_html = ""
    for f in report["findings"]:
        color = _SEV_COLOR.get(f["severity"], "#555")
        ev_html = "".join(f"<li><code>{e}</code></li>" for e in f["evidence"])
        ds = f.get("delta_state")
        delta_html = ""
        if ds and ds in _DELTA_STYLE:
            label, bg, txt = _DELTA_STYLE[ds]
            delta_html = (f"<span style='background:{bg};color:{txt};"
                          f"border-radius:3px;padding:.15rem .45rem;"
                          f"font-size:.7rem;font-weight:700'>{label}</span>")
        findings_html += f"""
<div class='finding' style='border-left:4px solid {color}'>
  <div class='fhead'>
    <span class='fid'>{f['check_id']}</span>
    <span class='ftitle'>{f['title']}</span>
    <span class='fsev' style='background:{color}'>{f['severity'].upper()}</span>
    {delta_html}
  </div>
  <div class='fmeta'><span>📋 {f['cis']}</span><span>🏷️ {f['category']}</span></div>
  <p>{f['description']}</p>
  {'<ul>' + ev_html + '</ul>' if ev_html else ''}
</div>"""

    delta = report.get("delta")
    resolved_html = ""
    if delta and delta.get("resolved"):
        resolved_html = "<h2 style='color:#3fb950;margin-top:2rem'>✅ Resueltos desde baseline</h2>"
        for r in delta["resolved"]:
            rc = _SEV_COLOR.get(r.get("severity", ""), "#555")
            resolved_html += (
                f"<div class='finding' style='border-left:4px solid {rc};opacity:.7'>"
                f"<div class='fhead'>"
                f"<span class='fid'>{r.get('check_id','')}</span>"
                f"<span class='ftitle'>{r.get('title','')}</span>"
                f"<span class='fsev' style='background:{rc}'>{r.get('severity','').upper()}</span>"
                f"<span style='background:#1a4a1a;color:#3fb950;border-radius:3px;"
                f"padding:.15rem .45rem;font-size:.7rem;font-weight:700'>✅ FIXED</span>"
                f"</div></div>"
            )

    if not report["findings"]:
        findings_html = "<div class='ok'>✅ No se detectaron fallos de configuración</div>"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>vamp-windows-audit — {report['target']}</title>
<style>
:root{{--bg:#0d1117;--fg:#c9d1d9;--card:#161b22;--border:#30363d;--accent:#58a6ff}}
body{{background:var(--bg);color:var(--fg);font-family:'Segoe UI',system-ui,sans-serif;margin:0;padding:2rem}}
h1{{color:var(--accent);margin-bottom:.25rem}}
.meta{{color:#8b949e;font-size:.85rem;margin-bottom:1.5rem}}
.summary{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
.badge{{border-radius:4px;padding:.25rem .6rem;font-size:.8rem;font-weight:700;color:#fff}}
.finding{{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:1rem;margin-bottom:1rem}}
.fhead{{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;margin-bottom:.5rem}}
.fid{{color:#8b949e;font-size:.8rem;font-family:monospace}}
.ftitle{{font-weight:600;flex:1}}
.fsev{{border-radius:3px;padding:.15rem .5rem;font-size:.75rem;font-weight:700;color:#fff}}
.fmeta{{display:flex;gap:1rem;font-size:.8rem;color:#8b949e;margin-bottom:.5rem}}
.finding p{{margin:.25rem 0;font-size:.9rem}}
ul{{margin:.25rem 0;padding-left:1.25rem}}
code{{background:#0d1117;padding:.1rem .3rem;border-radius:3px;font-size:.85rem;color:#79c0ff}}
.ok{{background:var(--card);border:1px solid #238636;border-radius:6px;padding:1.5rem;
     color:#3fb950;text-align:center;font-size:1.1rem}}
</style>
</head>
<body>
<h1>🪟 vamp-windows-audit</h1>
<div class='meta'>
  Target: <b>{report['target']}</b> · OS: {report['os']} ·
  {report['generated'][:19].replace('T', ' ')} UTC
  {(' · Case: ' + report['case']) if report['case'] else ''}
  {(' · Analyst: ' + report['analyst']) if report['analyst'] else ''}
</div>
<div class='summary'>
  {badge('critical', s['critical'])}
  {badge('high', s['high'])}
  {badge('medium', s['medium'])}
  {badge('low', s.get('low', 0))}
  <span style='color:#8b949e;font-size:.85rem'>{s['total']} hallazgos / 15 checks</span>
</div>
{findings_html}
{resolved_html}
</body>
</html>"""


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="Windows Security Configuration Auditor — 15 CIS checks",
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--from-json", "-p", metavar="FILE",
                     help="Analyze pre-collected audit JSON (cross-platform)")
    src.add_argument("--collect", action="store_true",
                     help="Collect and analyze locally (requires Windows + PowerShell as Administrator)")
    src.add_argument("--collect-script", action="store_true",
                     help="Print the PowerShell collection script to stdout")

    parser.add_argument("--json", metavar="FILE", help="Save JSON report to file")
    parser.add_argument("--html", metavar="FILE", help="Save HTML report to file")
    parser.add_argument("--case",    default="", help="Case/engagement identifier")
    parser.add_argument("--analyst", default="", help="Analyst name")
    parser.add_argument("--severity", nargs="+",
                        choices=["critical", "high", "medium", "low"],
                        help="Filter findings by severity")
    parser.add_argument("--baseline", metavar="FILE",
                        help="Previous JSON report for delta comparison "
                             "(marks findings as NEW/RECURRING, lists RESOLVED)")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress output (exit code only)")
    parser.add_argument("--version", action="version",
                        version=f"{TOOL} {VERSION}")

    args = parser.parse_args(argv)

    if args.collect_script:
        print(COLLECT_SCRIPT)
        return 0

    if args.collect:
        info = WinInfo.collect_local()
    elif args.from_json:
        try:
            info = WinInfo.from_json(args.from_json)
        except Exception as exc:
            print(f"[ERROR] No se pudo leer el fichero JSON: {exc}", file=sys.stderr)
            return 3
    else:
        parser.print_help()
        return 3

    if info.error:
        print(f"[ERROR] {info.error}", file=sys.stderr)
        return 3

    findings = scan(info)

    if args.severity:
        findings = [f for f in findings if f.severity in args.severity]

    resolved: Optional[List[dict]] = None
    if args.baseline:
        try:
            findings, resolved = apply_delta(findings, args.baseline)
        except ValueError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 3

    report = build_report(info, findings, args.case, args.analyst, resolved)

    if args.json:
        with open(args.json, "w") as fp:
            json.dump(report, fp, indent=2, ensure_ascii=False)

    if args.html:
        with open(args.html, "w") as fp:
            fp.write(render_html(report))

    if not args.quiet:
        _ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        _DELTA = {"new": " [NEW]", "recurring": " [REC]"}
        print(f"\n{TOOL} v{VERSION} — {report['target']}")
        print("─" * 60)
        if findings:
            for f in findings:
                icon = _ICON.get(f.severity, "⚪")
                delta_tag = _DELTA.get(f.delta_state or "", "")
                print(f"{icon}{delta_tag} [{f.check_id}] {f.title} ({f.severity.upper()})")
                if f.evidence:
                    print(f"   └─ {f.evidence[0]}")
        else:
            print("✅ No se detectaron fallos de configuración")
        if resolved:
            print("\n✅ RESOLVED since baseline:")
            for r in resolved:
                print(f"   [{r.get('check_id','')}] {r.get('title','')} "
                      f"({r.get('severity','').upper()})")
        s = report["summary"]
        print("─" * 60)
        print(f"CRITICAL: {s['critical']}  HIGH: {s['high']}  "
              f"MEDIUM: {s['medium']}  LOW: {s.get('low', 0)}")

    s = report["summary"]
    if s["critical"] > 0:
        return 2
    if s["high"] > 0 or s["medium"] > 0:
        return 1
    return 0


def main_entry() -> None:
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
