# Day 2: Attacker Deployment & Network Unification

### Objective
---
*To integrate a controlled adversary node (Kali Linux) into the SOC lab environment and establish a unified communication channel between the Attacker (Kali), the Victim (Windows 10), and the SIEM (Wazuh).*
---
### 1. Attacker Node Deployment
- **Operating System:** Kali Linux 2026.x (Debian-based)
- **Installation Highlights:**
   - Configured a virtualized instance within VMware.
   - Set up a primary user and established the GRUB bootloader on /dev/sda for independent disk booting.
   - Installed VMware Tools to ensure seamless clipboard sharing and display scaling for efficient lab work.
---
### 2. The "Invisible" Agent (Telemetry Collection)
To maintain a "Purple Team" perspective, a Wazuh agent was installed on the Kali Linux machine. This allows for the monitoring of the attacker's own activities, providing a complete picture of the attack lifecycle.
- **Deployment Method:** DEB amd64 package.
- **Service Management:**
   - sudo systemctl enable wazuh-agent
   - sudo systemctl start wazuh-agent
- **Verification**: Confirmed both the Windows and Kali nodes are Active in the Wazuh dashboard.
---
### 3. Network Troubleshooting & Mitigation
During deployment, a subnet mismatch was identified that prevented cross-node communication.
- **Issue:** Assets were distributed across 192.168.199.0/24 and 192.168.22.0/24.
- **Resolution**
    - Migrated all Virtual Network Adapters to the VMnet8 (NAT) virtual switch.
    - Performed an ipconfig /release and /renew on the Windows host to lease a new IP address in the unified 192.168.22.x range.
    - Updated the ossec.conf file on both endpoints to point to the new Wazuh Manager IP.
---
### 4. Host-Based Security & ICMP Reachability
Even with the unified networking, the Kali Linux node could not reach the Windows host due to the default firewall policies.
- **The Problem:** Windows Defender Firewall drops unsolicited ICMP Echo Requests by default.
- **The Fix:**
    - Created a custom Inbound Firewall Rule titled Allow_Lab_Ping
    - **Protocol:** ICMPv4
    - **Scope:** Restricted to the local lab subnet for security best practices.
- **Validation:** Confirmed bi-directional "handshakes" between Kali and Windows
---
## Evidence of Connectivity
- **Successful Ping:** ![Windows to Kali](../images/day2-ping-win-to-kali.png)
- **Successful Ping:** ![Kali to Windows](../images/day2-ping-kali-to-win.png)
- **Custom Firewall Rule** ![Custom Firewall Rule](../images/day2-firewall-rule-setup.png)
- **Wazuh Active Agents** ![Wazuh Active Agents](../images/day2-wazuh-agents-active.png)
