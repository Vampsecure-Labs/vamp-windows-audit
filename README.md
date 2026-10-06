# vamp-windows-audit

Windows Security Configuration Auditor — 15 CIS-aligned checks for authorized security testing.

## Overview

`vamp-windows-audit` analyzes Windows system configurations for common security misconfigurations. Data collection runs as a PowerShell script on the target; analysis can run on any platform (Linux, macOS, Windows) from the collected JSON.

## Checks (WIN-001..015)

| ID | Title | Severity | CIS |
|----|-------|----------|-----|
| WIN-001 | SMBv1 habilitado | CRITICAL | CIS 18.3.3 |
| WIN-002 | Cuenta Guest activa | HIGH | CIS 2.3.1.3 |
| WIN-003 | Cuenta Administrator sin renombrar | MEDIUM | CIS 2.3.1.1 |
| WIN-004 | Complejidad de contraseña desactivada | HIGH | CIS 1.1.5 |
| WIN-005 | Umbral de bloqueo de cuenta no configurado | HIGH | CIS 1.2.2 |
| WIN-006 | UAC desactivado | CRITICAL | CIS 2.3.17.1 |
| WIN-007 | Windows Firewall desactivado (algún perfil) | HIGH | CIS 9.1-9.3 |
| WIN-008 | RDP sin Network Level Authentication (NLA) | HIGH | CIS 18.9.52.1 |
| WIN-009 | Windows Defender / AV desactivado | CRITICAL | CIS 18.9.47.4 |
| WIN-010 | Actualizaciones automáticas desactivadas | MEDIUM | CIS 18.9.8 |
| WIN-011 | Auditoría de inicio de sesión no configurada | MEDIUM | CIS 17.5.1 |
| WIN-012 | PowerShell con política de ejecución irrestricta | MEDIUM | CIS 18.9.76.1 |
| WIN-013 | Servicio Remote Registry activo | MEDIUM | CIS 2.2.28 |
| WIN-014 | LAPS no desplegado | MEDIUM | CIS 2.3.1 (ext.) |
| WIN-015 | Null Session Pipes sin restringir | HIGH | CIS 2.3.10.3 |

## Installation

```bash
pip install vamp-windows-audit
```

## Usage

### Two-step workflow (cross-platform)

**Step 1 — collect on the Windows target** (requires PowerShell, run as Administrator):

```bash
vamp-windows-audit --collect-script | Set-Content collect.ps1
powershell -ExecutionPolicy Bypass -File collect.ps1 > audit.json
```

**Step 2 — analyze from any machine**:

```bash
vamp-windows-audit --from-json audit.json
vamp-windows-audit --from-json audit.json --html report.html
vamp-windows-audit --from-json audit.json --json report.json
```

### Collect and analyze locally (Windows only, as Administrator)

```bash
vamp-windows-audit --collect
```

### Options

```
--from-json FILE    Analyze pre-collected JSON (cross-platform)
--collect           Collect and analyze locally (Windows + Admin)
--collect-script    Print the PowerShell collection script to stdout
--json FILE         Save JSON report
--html FILE         Save HTML report
--case TEXT         Case/engagement identifier
--analyst TEXT      Analyst name
--severity ...      Filter by severity (critical high medium low)
--quiet             Exit code only, no output
--version           Show version
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | HIGH or MEDIUM findings only |
| 2 | At least one CRITICAL finding |
| 3 | Error (invalid input, file not found, etc.) |

## License

AGPL-3.0-only — for authorized security testing only.

© VampSecure Studios — VampSecure Labs Security Research Division
