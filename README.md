# vamp-windows-audit

**VampSecure Labs · Security Research Division**

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

Windows Security Configuration Auditor — 15 CIS-aligned checks for authorized security testing.

### Overview

`vamp-windows-audit` analyzes Windows system configurations for common security misconfigurations. Data collection runs as a PowerShell script on the target; analysis can run on any platform (Linux, macOS, Windows) from the collected JSON.

### Checks (WIN-001..015)

| ID | Title | Severity | CIS |
|----|-------|----------|-----|
| WIN-001 | SMBv1 enabled | CRITICAL | CIS 18.3.3 |
| WIN-002 | Guest account active | HIGH | CIS 2.3.1.3 |
| WIN-003 | Administrator account not renamed | MEDIUM | CIS 2.3.1.1 |
| WIN-004 | Password complexity disabled | HIGH | CIS 1.1.5 |
| WIN-005 | Account lockout threshold not configured | HIGH | CIS 1.2.2 |
| WIN-006 | UAC disabled | CRITICAL | CIS 2.3.17.1 |
| WIN-007 | Windows Firewall disabled (any profile) | HIGH | CIS 9.1-9.3 |
| WIN-008 | RDP without Network Level Authentication (NLA) | HIGH | CIS 18.9.52.1 |
| WIN-009 | Windows Defender / AV disabled | CRITICAL | CIS 18.9.47.4 |
| WIN-010 | Automatic updates disabled | MEDIUM | CIS 18.9.8 |
| WIN-011 | Logon auditing not configured | MEDIUM | CIS 17.5.1 |
| WIN-012 | PowerShell execution policy unrestricted | MEDIUM | CIS 18.9.76.1 |
| WIN-013 | Remote Registry service active | MEDIUM | CIS 2.2.28 |
| WIN-014 | LAPS not deployed | MEDIUM | CIS 2.3.1 (ext.) |
| WIN-015 | Null Session Pipes unrestricted | HIGH | CIS 2.3.10.3 |

### Installation

```bash
pip install vamp-windows-audit
```

### Usage

#### Two-step workflow (cross-platform)

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

#### Collect and analyze locally (Windows only, as Administrator)

```bash
vamp-windows-audit --collect
```

#### Options

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

#### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | HIGH or MEDIUM findings only |
| 2 | At least one CRITICAL finding |
| 3 | Error (invalid input, file not found, etc.) |

### Sample Output

```
# Step 1 — collect on the Windows target (run as Administrator in PowerShell)
PS C:\> vamp-windows-audit --collect-script | Set-Content collect.ps1
PS C:\> powershell -ExecutionPolicy Bypass -File collect.ps1 > audit.json

# Step 2 — analyze from any machine
$ vamp-windows-audit --from-json audit.json --case AUDIT-2026-019

╭──────────────────────────────────────────────────────────────────╮
│  vamp-windows-audit v1.0 — Windows Security Auditor              │
│  VampSecure Labs · Target: WORKSTATION-07 (Windows 11 Pro 23H2)  │
│  Case: AUDIT-2026-019                                            │
╰──────────────────────────────────────────────────────────────────╯

╭─ CRITICAL — WIN-001 ────────────────────────────────────────────╮
│ SMBv1 enabled                                                    │
│ Current : SMBv1 = Enabled                                        │
│ Expected: Disabled                                               │
│ Risk    : EternalBlue / WannaCry exploitation vector             │
│           (CVE-2017-0144, CVSS 9.3)                             │
│ Fix     : Set-SmbServerConfiguration -EnableSMB1Protocol $false  │
╰──────────────────────────────────────────────────────────────────╯

╭─ CRITICAL — WIN-006 ────────────────────────────────────────────╮
│ UAC disabled                                                     │
│ Current : HKLM\...\EnableLUA = 0                                 │
│ Expected: EnableLUA = 1                                          │
│ Risk    : Every process runs with full administrator token       │
╰──────────────────────────────────────────────────────────────────╯

╭─ HIGH — WIN-004 ────────────────────────────────────────────────╮
│ Password complexity not enforced                                 │
│ Current : PasswordComplexity = 0                                 │
│ Fix     : secedit /configure → PasswordComplexity = 1           │
╰──────────────────────────────────────────────────────────────────╯

╭─ HIGH — WIN-008 ────────────────────────────────────────────────╮
│ RDP without Network Level Authentication (NLA)                   │
│ Current : UserAuthentication = 0 · NLA disabled                  │
│ Risk    : Pre-authentication attack surface exposed              │
╰──────────────────────────────────────────────────────────────────╯

╭─ MEDIUM — WIN-012 ──────────────────────────────────────────────╮
│ PowerShell execution policy unrestricted                         │
│ Current : ExecutionPolicy = Unrestricted                         │
│ Fix     : Set-ExecutionPolicy RemoteSigned -Scope LocalMachine   │
╰──────────────────────────────────────────────────────────────────╯

┌──────────┬──────────────────────────────────────────────────────┐
│ Severity │ Count                                                │
├──────────┼──────────────────────────────────────────────────────┤
│ CRITICAL │ 2                                                    │
│ HIGH     │ 4                                                    │
│ MEDIUM   │ 5                                                    │
│ LOW      │ 1                                                    │
│ PASS     │ 3                                                    │
└──────────┴──────────────────────────────────────────────────────┘
Exit code: 2 (at least one CRITICAL finding)
```

### Why vamp-windows-audit vs. CIS-CAT Pro · Lynis · PowerShell DSC

| Feature | vamp-windows-audit | CIS-CAT Pro | Lynis | PowerShell DSC |
|---------|:-----------------:|:-----------:|:-----:|:--------------:|
| Cross-platform analysis (collect on Windows, analyze on Linux/macOS) | ✅ | ❌ Java on analyst machine | ❌ Linux only | ❌ Windows only |
| Free and open source | ✅ AGPL-3.0 | ❌ paid license | ✅ GPL | ✅ |
| JSON + HTML dark-theme reports | ✅ | ✅ | ⚠️ plain text / XML | ❌ |
| CIS Benchmark + STIG + NIST SP 800-171 aligned | ✅ | ✅ CIS only | ⚠️ Linux CIS | ⚠️ custom config |
| Baseline diff (`--baseline FILE`) | ✅ | ⚠️ paid tier | ❌ | ⚠️ config drift only |
| CI/CD exit codes | ✅ | ❌ | ⚠️ | ⚠️ |
| Case + analyst metadata in report | ✅ | ⚠️ | ❌ | ❌ |
| Zero cloud dependency | ✅ | ❌ cloud-based scoring | ✅ | ✅ |

- **Cross-platform by design**: the PowerShell collection script outputs a portable JSON file that can be analyzed on any OS; auditors running Linux or macOS do not need a Windows VM to review findings.
- **Baseline comparison**: `--baseline FILE` accepts a previous audit JSON and highlights regressions — useful for tracking hardening progress across sprint cycles or verifying that a remediation actually landed.
- **Audit-ready output**: findings include CIS Benchmark section numbers, STIG VULN IDs, and NIST SP 800-171 control references, meeting the evidence format expected by most compliance engagements.
- **No licensing friction**: unlike CIS-CAT Pro, `vamp-windows-audit` ships under AGPL-3.0 — drop it into a CI pipeline, air-gapped lab, or client-side assessment without purchasing per-seat licenses.

### Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| WIN-001 | SMBv1 protocol enabled — EternalBlue / WannaCry vector (CVE-2017-0144) | CIS 18.3.3 · STIG V-220906 | CRITICAL |
| WIN-002 | Built-in Guest account active | CIS 2.3.1.3 · NIST SP 800-171 3.1.1 | HIGH |
| WIN-003 | Built-in Administrator account not renamed | CIS 2.3.1.1 · STIG V-220730 | MEDIUM |
| WIN-004 | Password complexity requirement disabled | CIS 1.1.5 · NIST SP 800-171 3.5.7 | HIGH |
| WIN-005 | Account lockout threshold not configured | CIS 1.2.2 · NIST SP 800-171 3.5.6 | HIGH |
| WIN-006 | User Account Control (UAC) disabled | CIS 2.3.17.1 · STIG V-220947 | CRITICAL |
| WIN-007 | Windows Firewall disabled in at least one network profile | CIS 9.1–9.3 · NIST SP 800-171 3.13.1 | HIGH |
| WIN-008 | RDP without Network Level Authentication (NLA) | CIS 18.9.52.1 · STIG V-220999 | HIGH |
| WIN-009 | Windows Defender / antimalware protection disabled | CIS 18.9.47.4 · NIST SP 800-171 3.14.2 | CRITICAL |
| WIN-010 | Automatic updates disabled | CIS 18.9.8 · NIST SP 800-171 3.14.1 | MEDIUM |
| WIN-011 | Logon auditing not configured (success and failure) | CIS 17.5.1 · NIST SP 800-171 3.3.1 | MEDIUM |
| WIN-012 | PowerShell execution policy set to Unrestricted | CIS 18.9.76.1 · STIG V-220965 | MEDIUM |
| WIN-013 | Remote Registry service running and exposed | CIS 2.2.28 · STIG V-220757 | MEDIUM |
| WIN-014 | LAPS (Local Administrator Password Solution) not deployed | CIS 2.3.1 (ext.) · NIST SP 800-171 3.5.2 | MEDIUM |
| WIN-015 | Null session pipes not restricted (anonymous network access) | CIS 2.3.10.3 · STIG V-220874 | HIGH |

### Version History

| Version | Main changes |
|---------|-------------|
| v1.1.1 | Bilingual README (EN/ES) |
| v1.1.0 | Delta scan (`--baseline FILE`) |
| v1.0.0 | Initial release — 15 CIS-aligned checks, cross-platform analysis |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For use in authorized audits only. Unauthorized use is illegal.

---
---

<a name="español"></a>
## 🇪🇸 Español

Auditor de configuración de seguridad Windows — 15 checks alineados con CIS para pruebas de seguridad autorizadas.

### Descripción general

`vamp-windows-audit` analiza configuraciones de sistemas Windows en busca de errores de configuración de seguridad comunes. La recogida de datos se ejecuta como script PowerShell en el objetivo; el análisis puede ejecutarse en cualquier plataforma (Linux, macOS, Windows) a partir del JSON recopilado.

### Checks (WIN-001..015)

| ID | Título | Severidad | CIS |
|----|--------|-----------|-----|
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

### Instalación

```bash
pip install vamp-windows-audit
```

### Uso

#### Flujo de trabajo en dos pasos (multiplataforma)

**Paso 1 — recoger en el objetivo Windows** (requiere PowerShell, ejecutar como Administrador):

```bash
vamp-windows-audit --collect-script | Set-Content collect.ps1
powershell -ExecutionPolicy Bypass -File collect.ps1 > audit.json
```

**Paso 2 — analizar desde cualquier máquina**:

```bash
vamp-windows-audit --from-json audit.json
vamp-windows-audit --from-json audit.json --html informe.html
vamp-windows-audit --from-json audit.json --json informe.json
```

#### Recoger y analizar localmente (solo Windows, como Administrador)

```bash
vamp-windows-audit --collect
```

#### Opciones

```
--from-json FICHERO   Analizar JSON pre-recopilado (multiplataforma)
--collect             Recoger y analizar localmente (Windows + Admin)
--collect-script      Imprimir el script PowerShell de recogida en stdout
--json FICHERO        Guardar informe JSON
--html FICHERO        Guardar informe HTML
--case TEXTO          Identificador de caso/encargo
--analyst TEXTO       Nombre del analista
--severity ...        Filtrar por severidad (critical high medium low)
--quiet               Solo exit code, sin salida
--version             Mostrar versión
```

#### Exit codes

| Código | Significado |
|--------|-------------|
| 0 | Sin hallazgos |
| 1 | Solo hallazgos HIGH o MEDIUM |
| 2 | Al menos un hallazgo CRITICAL |
| 3 | Error (entrada inválida, fichero no encontrado, etc.) |

### Ejemplo de salida

```
# Paso 1 — recoger en el objetivo Windows (ejecutar como Administrador en PowerShell)
PS C:\> vamp-windows-audit --collect-script | Set-Content collect.ps1
PS C:\> powershell -ExecutionPolicy Bypass -File collect.ps1 > audit.json

# Paso 2 — analizar desde cualquier máquina
$ vamp-windows-audit --from-json audit.json --case AUDIT-2026-019

╭──────────────────────────────────────────────────────────────────╮
│  vamp-windows-audit v1.0 — Windows Security Auditor              │
│  VampSecure Labs · Target: WORKSTATION-07 (Windows 11 Pro 23H2)  │
│  Case: AUDIT-2026-019                                            │
╰──────────────────────────────────────────────────────────────────╯

╭─ CRITICAL — WIN-001 ────────────────────────────────────────────╮
│ SMBv1 habilitado                                                 │
│ Actual  : SMBv1 = Enabled                                        │
│ Esperado: Disabled                                               │
│ Riesgo  : Vector de explotación EternalBlue / WannaCry           │
│           (CVE-2017-0144, CVSS 9.3)                             │
│ Solución: Set-SmbServerConfiguration -EnableSMB1Protocol $false  │
╰──────────────────────────────────────────────────────────────────╯

╭─ CRITICAL — WIN-006 ────────────────────────────────────────────╮
│ UAC desactivado                                                  │
│ Actual  : HKLM\...\EnableLUA = 0                                 │
│ Esperado: EnableLUA = 1                                          │
│ Riesgo  : Todos los procesos se ejecutan con token de admin completo │
╰──────────────────────────────────────────────────────────────────╯

╭─ HIGH — WIN-004 ────────────────────────────────────────────────╮
│ Complejidad de contraseña no aplicada                            │
│ Actual  : PasswordComplexity = 0                                 │
│ Solución: secedit /configure → PasswordComplexity = 1           │
╰──────────────────────────────────────────────────────────────────╯

╭─ HIGH — WIN-008 ────────────────────────────────────────────────╮
│ RDP sin Network Level Authentication (NLA)                       │
│ Actual  : UserAuthentication = 0 · NLA desactivado               │
│ Riesgo  : Superficie de ataque pre-autenticación expuesta        │
╰──────────────────────────────────────────────────────────────────╯

╭─ MEDIUM — WIN-012 ──────────────────────────────────────────────╮
│ Política de ejecución de PowerShell irrestricta                  │
│ Actual  : ExecutionPolicy = Unrestricted                         │
│ Solución: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine   │
╰──────────────────────────────────────────────────────────────────╯

┌──────────┬──────────────────────────────────────────────────────┐
│ Severity │ Count                                                │
├──────────┼──────────────────────────────────────────────────────┤
│ CRITICAL │ 2                                                    │
│ HIGH     │ 4                                                    │
│ MEDIUM   │ 5                                                    │
│ LOW      │ 1                                                    │
│ PASS     │ 3                                                    │
└──────────┴──────────────────────────────────────────────────────┘
Exit code: 2 (at least one CRITICAL finding)
```

### Por qué vamp-windows-audit vs. CIS-CAT Pro · Lynis · PowerShell DSC

| Característica | vamp-windows-audit | CIS-CAT Pro | Lynis | PowerShell DSC |
|----------------|:-----------------:|:-----------:|:-----:|:--------------:|
| Análisis multiplataforma (recoger en Windows, analizar en Linux/macOS) | ✅ | ❌ Java en máquina del analista | ❌ solo Linux | ❌ solo Windows |
| Libre y de código abierto | ✅ AGPL-3.0 | ❌ licencia de pago | ✅ GPL | ✅ |
| Informes JSON + HTML dark-theme | ✅ | ✅ | ⚠️ texto plano / XML | ❌ |
| Alineado con CIS Benchmark + STIG + NIST SP 800-171 | ✅ | ✅ solo CIS | ⚠️ Linux CIS | ⚠️ config personalizada |
| Diff de línea base (`--baseline FILE`) | ✅ | ⚠️ tier de pago | ❌ | ⚠️ solo config drift |
| Exit codes CI/CD | ✅ | ❌ | ⚠️ | ⚠️ |
| Metadatos de caso y analista en el informe | ✅ | ⚠️ | ❌ | ❌ |
| Sin dependencia de la nube | ✅ | ❌ scoring basado en nube | ✅ | ✅ |

- **Multiplataforma por diseño**: el script PowerShell de recogida genera un fichero JSON portable que puede analizarse en cualquier SO; los auditores con Linux o macOS no necesitan una VM Windows para revisar los hallazgos.
- **Comparación con línea base**: `--baseline FILE` acepta un JSON de auditoría anterior y destaca las regresiones — útil para seguir el progreso del hardening entre ciclos de sprint o verificar que una corrección realmente se aplicó.
- **Salida lista para auditoría**: los hallazgos incluyen números de sección del CIS Benchmark, IDs VULN de STIG y referencias de control NIST SP 800-171, cumpliendo el formato de evidencia esperado en la mayoría de los encargos de cumplimiento.
- **Sin fricción de licencias**: a diferencia de CIS-CAT Pro, `vamp-windows-audit` se distribuye bajo AGPL-3.0 — intégralo en un pipeline CI, un laboratorio aislado o una evaluación en cliente sin adquirir licencias por puesto.

### Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|----------|-------------|----------|-----------|
| WIN-001 | Protocolo SMBv1 habilitado — vector EternalBlue / WannaCry (CVE-2017-0144) | CIS 18.3.3 · STIG V-220906 | CRITICAL |
| WIN-002 | Cuenta Guest integrada activa | CIS 2.3.1.3 · NIST SP 800-171 3.1.1 | HIGH |
| WIN-003 | Cuenta Administrator integrada sin renombrar | CIS 2.3.1.1 · STIG V-220730 | MEDIUM |
| WIN-004 | Requisito de complejidad de contraseña desactivado | CIS 1.1.5 · NIST SP 800-171 3.5.7 | HIGH |
| WIN-005 | Umbral de bloqueo de cuenta no configurado | CIS 1.2.2 · NIST SP 800-171 3.5.6 | HIGH |
| WIN-006 | Control de cuentas de usuario (UAC) desactivado | CIS 2.3.17.1 · STIG V-220947 | CRITICAL |
| WIN-007 | Windows Firewall desactivado en al menos un perfil de red | CIS 9.1–9.3 · NIST SP 800-171 3.13.1 | HIGH |
| WIN-008 | RDP sin Network Level Authentication (NLA) | CIS 18.9.52.1 · STIG V-220999 | HIGH |
| WIN-009 | Windows Defender / protección antimalware desactivada | CIS 18.9.47.4 · NIST SP 800-171 3.14.2 | CRITICAL |
| WIN-010 | Actualizaciones automáticas desactivadas | CIS 18.9.8 · NIST SP 800-171 3.14.1 | MEDIUM |
| WIN-011 | Auditoría de inicio de sesión no configurada (éxito y fallo) | CIS 17.5.1 · NIST SP 800-171 3.3.1 | MEDIUM |
| WIN-012 | Política de ejecución de PowerShell configurada como Unrestricted | CIS 18.9.76.1 · STIG V-220965 | MEDIUM |
| WIN-013 | Servicio Remote Registry en ejecución y expuesto | CIS 2.2.28 · STIG V-220757 | MEDIUM |
| WIN-014 | LAPS (Local Administrator Password Solution) no desplegado | CIS 2.3.1 (ext.) · NIST SP 800-171 3.5.2 | MEDIUM |
| WIN-015 | Null session pipes sin restringir (acceso anónimo a la red) | CIS 2.3.10.3 · STIG V-220874 | HIGH |

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.1.1 | README bilingüe (EN/ES) |
| v1.1.0 | Escaneo diferencial (`--baseline FILE`) |
| v1.0.0 | Versión inicial — 15 checks alineados con CIS, análisis multiplataforma |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Uso exclusivo en auditorías autorizadas. El uso no autorizado es ilegal.

## License

AGPL-3.0-only — for authorized security testing only.
