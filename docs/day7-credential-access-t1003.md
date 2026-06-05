# Exercise 4.1 — Credential Dumping: LSASS Memory Access (T1003.001)

**Date:** June 5, 2026  
**Technique:** OS Credential Dumping: LSASS Memory — T1003.001  
**Research Question:** Does Wazuh detect LSASS access in a default configuration?  
**ATT&CK Tactic:** Credential Access  
**Threat Actor Context:** APT29 uses LSASS credential dumping to harvest plaintext passwords and NTLM hashes for lateral movement. Play ransomware uses Mimikatz against LSASS as a standard pre-encryption step. This technique appears in the documented kill chains of nearly every sophisticated threat actor.

---

## Answer to Research Question

**No.** Wazuh does not detect LSASS access in a default configuration.

The attack was executed successfully and silently. The LSASS dump file was written to disk with no Wazuh alert generated. Detection required a custom Sysmon configuration explicitly targeting `ProcessAccess` events on `lsass.exe`, which is a non-default capability that must be deliberately engineered.

This finding has direct defensive implications: organizations running Wazuh with default Sysmon configurations have no visibility into one of the most commonly executed credential access techniques in the adversary playbook.

---

## Phase 1 — Initial Attack Execution

### Method

Used the LSASS memory dump technique via `rundll32.exe` + `comsvcs.dll`, which is a living-off-the-land approach that avoids dropping Mimikatz or any external tooling on disk.

```cmd
tasklist | findstr lsass.exe
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 664 C:\Windows\Temp\lsass.dmp full
```

`tasklist | findstr` confirmed LSASS running as PID 664. The `comsvcs.dll MiniDump` export then wrote a full memory dump of LSASS — capturing all cached credentials — to `C:\Windows\Temp\lsass.dmp`.

| Evidence | |
|---|---|
| LSASS PID confirmed (664) and dump command executed | ![Attack Execution](./images/t1003-lsass-dump-execution.png) |

---

## Phase 2 — Detection Gap Confirmed

### Wazuh Threat Hunt — No Results

Queried Wazuh Threat Hunting for LSASS access events immediately after execution:

```
data.win.eventdata.targetImage: "*lsass.exe" AND data.win.eventdata.sourceImage: "*rundll32.exe"
```

Searched twice across different time windows — both returned no results.

| Evidence | |
|---|---|
| Wazuh query — no results, first search | ![Blind Spot 1](./images/t1003-lsass-blind-spot-1.png) |
| Wazuh query — no results, 24-hour window | ![Blind Spot 2](./images/t1003-lsass-blind-spot-2.png) |

### Local Telemetry Validation

Opened Windows Event Viewer to confirm Sysmon was active — ruling out Sysmon being offline as the cause of the detection failure.

**Finding:** Sysmon was running and generating events. EID 5 (Process Termination) events from June 5 were visible, confirming the telemetry pipeline was live. The detection gap was a **configuration gap**, not an availability problem.

Sysmon's default configuration does not capture EID 10 (`ProcessAccess`) events; the event type generated when one process reads another's memory. LSASS credential dumping produces EID 10 events exclusively. With no EID 10 collection configured, the attack was invisible.

| Evidence | |
|---|---|
| Event Viewer — Sysmon operational, EID 255 errors and EID 5 events visible | ![Event Viewer 1](./images/t1003-event-viewer-sysmon-running.png) |
| Event Viewer — EID 5 process termination events from June 5 confirming active telemetry | ![Event Viewer 2](./images/t1003-event-viewer-process-terminated.png) |

**Root cause:** Sysmon's default configuration monitors process creation (EID 1) and network connections (EID 3) but does not monitor process memory access (EID 10) without explicit configuration. LSASS credential dumping is invisible without a `ProcessAccess` rule targeting `lsass.exe`.

---

## Phase 3 — Detection Engineering

### Step 1 — Custom Sysmon XML Configuration

Wrote `lsass-watch.xml` to capture all `ProcessAccess` events where `lsass.exe` is the target image:

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

`onmatch="include"` with `TargetImage` ending in `lsass.exe` captures any process attempting to access LSASS memory — regardless of the source process. This catches both known tools and unknown or renamed variants.

| Evidence | |
|---|---|
| `lsass-watch.xml` in Notepad | ![Sysmon XML](./images/t1003-sysmon-lsass-watch-xml.png) |

### Step 2 — Configuration Troubleshooting

Encountered errors during the first load attempts. Sysmon could not find `sysmon-config.xml` (incorrect filename referenced), and a reinstall attempt failed because Sysmon was already registered. Resolved by referencing `lsass-watch.xml` directly with the `-c` flag (update existing configuration) rather than `-i` (install).

| Evidence | |
|---|---|
| Sysmon config errors — wrong filename and already-registered conflict | ![Config Error](./images/t1003-sysmon-config-error.png) |

### Step 3 — Configuration Successfully Applied + Attack Re-Executed

Ran `sysmon64.exe -c lsass-watch.xml`. The configuration validated against schema version 4.50 and applied successfully. Immediately re-ran the LSASS dump to generate fresh telemetry under the updated configuration.

```cmd
sysmon64.exe -c lsass-watch.xml
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 664 C:\Windows\Temp\lsass.dmp full
```

| Evidence | |
|---|---|
| Sysmon config validated and updated — attack immediately re-executed | ![Config Loaded + Attack](./images/t1003-sysmon-config-loaded-attack-rerun.png) |

### Step 4 — Wazuh Agent Pipeline Update

Confirmed `ossec.conf` had the `Microsoft-Windows-Sysmon/Operational` channel correctly configured in the localfile block, then restarted the Wazuh agent to ensure the updated Sysmon EID 10 telemetry was being ingested.

```powershell
Stop-Service -Name "Wazuh"
Start-Service -Name "Wazuh"
```

| Evidence | |
|---|---|
| ossec.conf — Sysmon Operational channel in localfile block | ![ossec.conf](./images/t1003-ossec-conf-update.png) |
| Wazuh agent stop and start | ![Agent Restart](./images/t1003-wazuh-agent-restart.png) |

---

## Phase 4 — Detection Validated

Queried Wazuh Threat Hunting for `"Microsoft-Windows-Sysmon\Operational"` events — **Rule 92900 fired at the top of the results list**, Level 12:

> **"Lsass process was accessed by C:\\Pro... with read permissions, possible credential dump"**

Rule 92900 detail confirmed:
- **If_group:** `sysmon_event_10` — Sysmon EID 10 (Process Access)
- **Win.Eventdata.TargetImage:** `(?i)lsass\.exe` — PCRE2 match
- **Win.Eventdata.GrantedAccess:** `(?i)(0x1010|0x40)` — read permission flags consistent with credential dumping
- **MITRE Technique:** LSASS Memory | **Tactic:** Credential Access
- **Level 12** — high severity

| Evidence | |
|---|---|
| Wazuh Threat Hunting — Rule 92900 firing, Level 12, top of results | ![Rule Firing](./images/t1003-wazuh-rule-92900-firing.png) |
| Wazuh Rule 92900 detail — EID 10, PCRE2, MITRE Credential Access | ![Rule Detail](./images/t1003-wazuh-rule-92900-detail.png) |

---

## Analytical Findings

| Finding | Assessment |
|---|---|
| Does Wazuh detect LSASS access by default? | **No** — default Sysmon config does not capture EID 10 |
| Is LSASS dumping detectable with Wazuh? | **Yes** — after adding `ProcessAccess` rule to Sysmon config |
| Does Wazuh Rule 92900 fire correctly once telemetry is available? | **Yes** — Level 12, MITRE mapped, no custom rule engineering needed |
| Detection gap severity | **Critical** — present in nearly every sophisticated threat actor kill chain |

**Key lesson:** Detection engineering is not only about writing rules; it is equally about ensuring the telemetry pipeline provides the data those rules need to fire. Wazuh Rule 92900 existed and was correctly written the entire time. The gap was upstream in Sysmon's configuration, not in Wazuh's detection logic.

---

## Updated Detection Coverage Matrix

| Technique | ATT&CK ID | Detected | Method |
|---|---|---|---|
| Network Service Discovery | T1046 | Yes | Rules 92031 / 92032 |
| Scheduled Task Persistence | T1053.005 | Yes | Sysmon EID 1 — schtasks.exe process tree |
| PowerShell Execution | T1059.001 | Yes | Custom Rule 100050 — Level 12 |
| File Integrity Violation | T1565 | Yes | Wazuh FIM — real-time |
| LSASS Memory Dump | T1003.001 | Yes* | Wazuh Rule 92900 — requires custom Sysmon EID 10 config |

*Not detected in default configuration. Requires `ProcessAccess` rule in Sysmon targeting `lsass.exe`.

---

## Defensive Recommendation

Deploy the `lsass-watch.xml` Sysmon configuration on all Windows endpoints. This single change closes the LSASS visibility gap and enables Wazuh Rule 92900 without any additional rule engineering. For stronger prevention, enable Windows Credential Guard. This moves LSASS into an isolated virtualized environment where memory access yields no usable credential data even if EID 10 fires.
