## Day 6: Cyber Threat Intelligence (CTI) & Adversary Profiling

### **Objective**
To pivot from basic alert engineering to advanced Cyber Threat Intelligence (CTI) operations. This phase focuses on analyzing raw forensic endpoint telemetry captured during previous simulations, correlating live indicators against Open-Source Intelligence (OSINT) repositories, and mapping a target adversary's operational playbook.

---

### **Phase 1: Tactical Forensic Investigation & Analyst Notes**
Following the successful generation of custom SIEM Rule `100050` (Level 12 High Severity Alert), I transitioned into the role of a SOC/CTI Analyst to extract high-value forensic data points directly from the raw log payload.

#### **Forensic Metadata Extraction:**
* **Core Binary Utilized:** `powershell.exe`
  * *Analyst Assessment:* The adversary is utilizing native system utilities to execute code. This minimizes their on-disk footprint and evades basic signature detection mechanisms (**MITRE T1059.001 - Living off the Land**).
* **Explicit Execution Flags:** `-ExecutionPolicy Bypass -File`
  * *Analyst Assessment:* Represents a deliberate action to subvert default Windows script execution restrictions to run unsigned or untrusted code blocks.
* **Volatile File Path Location:** `C:\Windows\Temp\malicious_script.ps1`
  * *Analyst Assessment:* Execution out of a temporary directory is a high-confidence behavioral indicator often associated with secondary payload dropping, staging, or rapid post-exploitation activities.

**Evidence: Forensic Telemetry Ingestion**
![Wazuh Forensic Log Clues](../images/day5-cti-alert-dashboard.png)

---

### **Phase 2: Open-Source Intelligence (OSINT) Correlation**
To establish high-confidence attribution, I cross-referenced the extracted forensic indicators and behaviors against global threat intelligence indices. The techniques observed in our environment closely align with the documented historical playbooks of **APT29** (also tracked globally as *Cozy Bear* or *Midnight Blizzard*), a highly sophisticated state-sponsored cyber espionage group.

#### **Adversary Technique Mapping:**
* **Command and Scripting Interpreter: PowerShell (T1059.001):** Public CTI data confirms APT29 heavily leverages PowerShell to execute commands, unpack secondary payloads (such as *CozyCar* or *SeaDuke*), and bypass local execution controls during initial access and execution vectors.
* **Scheduled Task/Job: Scheduled Task (T1053.005):** Historical campaigns (including the *SolarWinds Compromise*) indicate that APT29 routinely establishes stealthy persistence within enterprise networks by creating or hijacking automated Windows scheduled tasks (`schtasks.exe`) to maintain long-term presence (such as *SUNSPOT* persistence).

---

#### **OSINT Verification Evidence**

**Evidence: MITRE ATT&CK T1059.001 Documentation for APT29**
![MITRE ATT&CK PowerShell Execution Tracking](../images/day6-mitre-apt29-t1059-osint.png)

**Evidence: MITRE ATT&CK T1053.005 Documentation for APT29**
![MITRE ATT&CK Scheduled Task Persistence Tracking](../images/day6-mitre-apt29-t1053-osint.png)

---

### **Phase 3: Defensive Intelligence Heatmap (MITRE ATT&CK Navigator)**
Using the **MITRE ATT&CK Navigator**, I constructed a tactical threat profile heatmap to visualize our security operations center's active detection coverage against this adversary's specific operational methodologies.

* **Highlights:** Represent the critical attack paths monitored, logged via Sysmon, and successfully flagged by our SIEM deployment over this lifecycle (including *PowerShell Execution*, *Scheduled Task Persistence*, and *User Execution*).

**Evidence: Adversary Playbook Heatmap**
![MITRE ATT&CK Navigator Heatmap](../images/day6-mitre-navigator-heatmap.png)

---

### **Phase 4: Structural Intrusion Analysis (The Diamond Model)**
To provide security leadership with an organized understanding of the event context, I mapped the active intrusion parameters to the industry-standard **Diamond Model of Intrusion Analysis**:

```text
          [ ADVERSARY ]
             (APT29)
             /     \
            /       \
  [ CAPABILITY ]-----[ INFRASTRUCTURE ]
(PowerShell Bypass /   (C:\Windows\Temp\
 Scheduled Tasks)       Local Directory)
            \       /
             \     /
           [ VICTIM ]
        (Windows Server /
        Enterprise Node)
```
* **Adversary:** APT29 (Attributed cyber espionage threat actor group).
* **Capability:** Custom PowerShell scripting leveraging execution policy subversion flags and persistence mechanisms.
* **Infrastructure:** Intrasystem volatile file storage paths (`\Temp\`) used to stage malicious code blocks.
* **Victim:** Target Windows Server instance representing a critical workstation or domain controller architecture.

---

### **CTI Analyst Triage Note & Verdict**
As an analyst, raw alerts require human context to differentiate malicious intent from business operations:

* **True Positive (TP) Verdict:** If telemetry reveals this script executing from an unprivileged path, communicating with external untrusted IP addresses, or spawning obfuscated child processes, this matches known *APT29* techniques. Immediate containment protocols should be initiated.
* **False Positive (FP) Verdict:** If a review of internal documentation reveals that a network administrator deployed this file name via an internal service account (`SYSTEM`) to conduct scheduled infrastructure maintenance, this represents a conflict of nomenclature. The indicator parameters must be refined to eliminate operational noise.

---

### **Analytical Conclusion**
By shifting focus from static, reactive rule-matching to holistic behavior tracking, this model proves that defensive monitoring teams can leverage open-source tactical matrices to accurately predict an adversary's next logical operational sequence and harden defenses before secondary actions occur.
