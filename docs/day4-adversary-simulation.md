## Day 4: Adversary Simulation & MITRE ATT&CK Mapping

### **Objective**
To transition from passive monitoring to active threat simulation by deploying a framework to mimic real-world adversary behavior and verifying the SIEM's detection capabilities.

### **1. Framework Automation (Atomic Red Team)**
To simulate realistic threats, I deployed Red Canary's **Invoke-AtomicRedTeam** framework framework on the Windows 10 Endpoint. I automated a clean installation path to map out the attack scripts directly to the system root.

* **Execution Policy Bypass:** `Set-ExecutionPolicy Bypass -Scope Process -Force`
* **Library Integration:** Scripted the manual extraction and structural alignment of the 122MB atomics library directly into `C:\AtomicRedTeam\atomics\`.
* ![PowerShell Installation Script](../images/Day4_Adversary_Images/atomic-execution.png)

### **2. Attack Execution: Persistence (MITRE ATT&CK T1053.005)**
Attackers frequently use scheduled tasks to maintain access to a compromised host across system reboots. I simulated this behavior by launching an Atomic test targeting **Technique T1053.005**.

* **Command:** `Invoke-AtomicTest T1053.005 -TestNumbers 1`
* **Host Impact:** Successfully forced the creation of two persistent tasks: `T1053_005_OnLogon` and `T1053_005_OnStartup`.

**Evidence**
* ![Atomic Scheduled Task](../images/Day4_Adversary_Images/atomic-task-start.png)

### **3. Blue Team Forensic Analysis**
Pivoting to the **Wazuh SIEM Dashboard**, I conducted a manual threat hunt focused on the last 15 minutes of event logs to track down the telemetry footprint.

* **Telemetry Verification:** Caught the raw process creation event where `powershell.exe` acted as the parent process to spawn `schtasks.exe`.
* **Key Artifacts Uncovered in JSON:**
  * **`data.win.eventdata.parentImage`**: Proved the process hierarchy origins (`powershell.exe`).
  * **`data.win.eventdata.commandLine`**: Captured the exact arguments used to register the backdoor tasks.

**Evidence**
* ![Wazuh JSON Payload](../images/Day4_Adversary_Images/wazuh-json-payload.png)

### **4. Remediation & Incident Response**
Following standard incident response procedures, the simulated threat was evicted from the host using the framework's native cleanup functions, returning the workstation to a verified baseline.
* **Cleanup Command:** `Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup`

**Evidence**
* ![Atomic Cleanup](../images/Day4_Adversary_Images/atomic-task-cleanup.png)
