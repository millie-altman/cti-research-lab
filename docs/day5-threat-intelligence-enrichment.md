## Day 5: Threat Indicator Enrichment & Detection Engineering

### **Objective**
To pivot from basic alert logging to Cyber Threat Intelligence (CTI) operations by engineering a custom detection rule that cross-references live endpoint behavior against known Indicators of Compromise (IoCs).

---

### **1. Threat Intelligence Database Curation**
Emulating an enterprise CTI workflow, I curated a local intelligence database using Wazuh's CDB Lists (Constant Data Base) format to track a high-severity file indicator associated with a known threat actor group.

* **Target Indicator (IoC):** `malicious_script.ps1`
* **Threat Actor Attribution Context:** `APT29_Campaign`
* **Database File Path:** `/var/ossec/etc/lists/custom-intel-blacklist`

**Evidence**
![Curated CDB List Configuration](../images/day5-cdb-list.png)

Next, the list was officially registered within the master SIEM configuration file (`ossec.conf`) under the ruleset block to enable active memory lookups.

**Evidence**
![Registered List Configuration](../images/day5-malicious-script-rule.png)

---

### **2. Final CTI Rule Engineering**
Following structural testing, I engineered a high-severity custom detection rule inside `local_rules.xml`. The logic is designed to intercept Windows Sysmon process creation telemetry, scan the command-line payload via a case-insensitive PCRE2 regex engine, and flag exact matches against our threat intel database.

```xml
  <rule id="100050" level="12">
    <if_sid>92029</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)malicious_script\.ps1</field>
    <description>CTI Match: System Log Contains Known Malicious Indicator</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
```

**Evidence** 
![Final Optimized Detection Rule](../images/day5-local-rules-config)

---

### **3. Operational Simulation & Verification**
Switching to the Windows Server endpoint, I opened an administrative PowerShell console and executed a command string explicitly calling the blacklisted indicator script to simulate an interactive threat encounter.

**Evidence**
![Windows PowerShell Execution](../images/day5-powershell-command.png)

The detection engine successfully intercepted the Sysmon process creation log, cross-referenced the command-line payload against the database, elevated the event to a **Level 12 High Severity Alert**, and correctly applied the **MITRE ATT&CK Mapping (T1059.001 - PowerShell Command and Scripting Interpreter)**.

**Evidence**
![Successful Custom CTI Alert Dashboard](../images/day5-cti-alert-dashboard.png)

---

### **4. CTI Analyst Triage Note & Verdict**
As an analyst, raw alerts require human context to differentiate malicious intent from business operations:

* **True Positive (TP) Indicators:** If the telemetry reveals this script executing from an unprivileged path (like `\Temp\`), communicating with external untrusted IP addresses, or spawning obfuscated child processes, this matches known *APT29* techniques. Immediate containment protocols should be initiated.
* **False Positive (FP) Indicators:** If a review of internal documentation reveals that a network administrator deployed this file name via an internal service account (`SYSTEM`) to conduct maintenance, this represents a conflict of nomenclature. The indicator parameters must be refined to eliminate operational noise.

---

### **5. Lessons Learned & Troubleshooting Section**
Engineering a custom SIEM pipeline requires precise data parsing. Below is the step-by-step troubleshooting path required to resolve rule mismatches and engine compilation hurdles:

#### **Hurdle 1: The Global Match Tag Limitation**
Initially, I attempted to build a broad rule utilizing a top-level `<match>` tag to scan for the script string across the entire incoming log package.

**Evidence**
![Broad Match Tag Attempt](../images/day5-rule-config-error.png)

* **The Issue:** The rule failed to trigger because the `<match>` tag only scans the raw syslog header block. Because Sysmon stores process command-line strings deep within nested field objects, the tag missed the indicator entirely.

#### **Hurdle 2: Category and Field Incompatibilities**
In the second iteration, I attempted to bypass parent rule dependencies entirely by using a broad `<category>ossec</category>` classification while targeting the command-line field path.

**Evidence**
![Category Block Incompatibility](../images/day5-rule-config-error-2.png)

* **The Issue:** The manager failed to parse this cleanly because Windows Event Forwarding logs process data within specific event IDs (`EID 1` for process creation). Without declaring a valid parent rule ID dependency (`<if_sid>92029</if_sid>`), the engine could not map the explicit `win.eventdata` structural tree.

#### **Hurdle 3: Syntax and Variable Key-Value Testing**
During lookup testing, I implemented a strict key-value lookup check (`lookup="match_key_value"`) referencing the database path to dynamically pull out the string text into the alert description.

**Evidence**
![Lookup Syntax Verification](../images/day5-error-local-rules.png)

* **The Issue:** While syntactically valid, strict key-value lookups fail if there are any trailing spaces or format mismatches between the active Windows event payload string and the flat CDB text list.

#### **Key Takeaway**
Modern enterprise detection engineering requires moving away from generic full-text matching in favor of **strict field targeting** and **explicit parent-rule dependencies**. This troubleshooting process directly illuminated how data flows through a SIEM parser before an alert is generated.
