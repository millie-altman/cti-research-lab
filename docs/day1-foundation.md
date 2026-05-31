# Project Goal
Establish a stable, isolated virtual environment for SOC analysis and attack simulation using VMware, Wazuh SIEM, and a Windows 10 Pro endpoint.

### Infrastructure Setup
**Hypervisor:** VMware Workstation Player.

**Network:** NAT (Isolated Virtual Network).

**SIEM:** Wazuh (Manager/Indexer/Dashboard) deployed via OVA.

**Endpoint:** Windows 10 Pro (Victim/Target).

### Technical Tasks Completed
**Network Configuration:** Verified connectivity between the Windows Endpoint and Wazuh Manager via ICMP (Ping).

**Agent Deployment:** Installed the Wazuh Agent on Windows 10 Pro and established a successful handshake with the Manager.

**Endpoint Hardening (Visibility):** Installed Sysmon 64 with network monitoring enabled (-i -n) to enhance log collection beyond standard Windows Event Logs.

### FIM Configuration

1. Modified the agent’s ossec.conf to enable Real-Time File Integrity Monitoring.

2. Configured a custom monitoring directory: C:\lab_monitor.

3. Resolved XML syntax errors in the configuration file to restore agent connectivity.

### Persistence
Created a VMware Snapshot ("Wazuh_and_FIM_Working") to provide a known-good recovery point.

### Validation Results
Wazuh Agent Status: Active

### FIM Test
Successfully generated "File Added," "File Modified," and "File Deleted" alerts in the Wazuh Dashboard within seconds of local file changes.
