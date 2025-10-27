First, I set up the lab environment by installing VMware Workstation Pro 17 and configuring two virtual machines:

- **Kali Linux** as the Manager
- **Ubuntu** as the Agent

Both virtual machines were successfully deployed and fully operational, as demonstrated in the screenshots below.

![Ubuntu Screenshot](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/ubuntu.png)

![kali linux](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/kali%20linux.png)

Next, I installed the Wazuh Manager on the Kali Linux virtual machine.  
I followed the official Wazuh documentation and utilized the provided commands to complete the installation and initial configuration successfully.

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Finally, I obtained the manager credentials (username and password) required to access the Wazuh web interface.

```bash
username: admin
password: WKykYG..NSLmkic7LfX5z6mCI99kdh1T
```

I accessed the Wazuh web interface by navigating to `localhost` in the browser, which successfully loaded the dashboard automatically.

![wazuh homepage](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/wazuh%20homepage.png)

Next, I deployed the Wazuh agents.  
One of the agents initially appeared as disconnected.  
I navigated to the **Active Agents** section to verify status and troubleshoot connectivity

![active agent](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/active%20agent.png)

I selected the **“Deploy New Agent”** option.  
On the Linux agent machine, I configured the agent with the name **ubuntu-agent** and set the IP address of the Kali Linux machine, which serves as the Wazuh Manager.

![new agent page](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/new%20agent%20page.png)

I executed the following command on the agent machine to complete the registration process:
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.0-1_amd64.deb && sudo WAZUH_MANAGER='192.168.148.128' WAZUH_AGENT_NAME='ubuntu-agent' dpkg -i ./wazuh-agent_4.14.0-1_amd64.deb
```

I ran the command on the Ubuntu agent machine and restarted the system to apply the configuration changes.

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

![ubuntu agent is deployed](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/ubuntu%20agent%20is%20deployed.png)

After refreshing the Wazuh dashboard, the newly configured agent appeared as **active**, confirming successful registration and connectivity.

![deploy agent ubuntu](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/deploy%20agent%20ubuntu.png)

![dashboard](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/dashboard.png)

# Lab 1: File Integrity Monitoring (FIM)

This lab demonstrates the configuration and monitoring of critical files and directories using Wazuh to detect unauthorized changes and maintain system integrity.

### 1. Configure FIM on the Agent (`ossec.conf`)
Edit the agent configuration file:
```bash
sudo nano /var/ossec/etc/ossec.conf
```
Add or update the `<syscheck>` section:
```xml
<syscheck>
    <directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
    <frequency>60</frequency> <!-- Scan every 60 seconds -->
</syscheck>
```
Save and exit the file.

### 2. Restart the Wazuh Agent
Apply the changes by restarting the agent:
```bash
sudo systemctl restart wazuh-agent
```

### 3. Create Test Files to Trigger FIM Alerts
Generate, modify, and remove test files on the agent to generate alerts:
```bash
sudo touch /root/testfile_wazuh
echo "testing file" | sudo tee /root/testfile_wazuh
sudo rm /root/testfile_wazuh
```
### 4. Verify FIM Activity in Agent Logs
Monitor the agent logs for syscheck or FIM-related events:
```bash
sudo tail -f /var/ossec/logs/ossec.log
```
### 5. Verify Connectivity and Manager Status
- **Confirm TCP connection** between agent and manager (port 1514):
```bash
# On Manager
sudo netstat -tulnp | grep 1514

# On Agent
nc -vz <manager_ip> 1514
```
- **Check Wazuh Manager service status:**
```bash
sudo systemctl status wazuh-manager
```

### 6. Verify Alerts in the Wazuh Dashboard
- Log into the Wazuh web interface.
- Navigate to the **FIM** or **Syscheck** section.
- Filter events by agent name or file changes to confirm alerts are generated correctly.

![FIM Events](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/FIM%20Events.png)

![FIM 2](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/FIM%202.png)

![FIM 3](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/FIM%203.png)

![FIM 4](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/FIM%204.png)

# Lab 2: Detecting SSH Brute-Force Attacks
### Laboratory Setup
- **Attacker Machine:** Kali Linux (with Hydra installed to perform brute-force attacks)
- **Victim Machine:** Ubuntu (Wazuh agent installed and SSH server enabled)
### Objective
Simulate SSH brute-force attacks on the Ubuntu system using Hydra from Kali Linux, and detect these attacks in real-time on the Wazuh dashboard.
### Steps Overview
### 1. Prepare the Ubuntu Victim
- Ensure SSH server is installed and running:
```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl enable --now ssh
```
- Verify that SSH port `22` is open and accessible.
- Install and configure the Wazuh agent, ensuring it is successfully connected to the Wazuh Manager.
### 2. Prepare the Kali Attacker
- Install Hydra for password brute-forcing:
```bash
sudo apt update
sudo apt install hydra
```
- Prepare a password list (e.g., `rockyou.txt` located at `/usr/share/wordlists/rockyou.txt`).
### 3. Launch the Brute-Force Attack
Execute Hydra to attempt SSH login on the Ubuntu victim:
```bash
sudo hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<ubuntu_ip> -t 4 -V
```
- Replace `<username>` with the target user (e.g., `root`).
- Replace `<ubuntu_ip>` with the IP address of the Ubuntu victim.
- `-t 4` sets concurrency level.
- `-V` enables verbose output to monitor progress.
### 4. Monitor Wazuh Dashboard for Alerts
- Log in to the Wazuh dashboard.
- Navigate to **Threat Hunting** or **Security Events**.
- Apply filters to detect brute-force alerts:

**Linux rules:**
```text
rule.id:(5551 OR 5712 OR 5710 OR 5711 OR 5716 OR 5720 OR 5503 OR 5504
```
**Windows rules (if applicable):**
```text
rule.id:(60122 OR 60204)
```
- Observe authentication failure alerts and correlate them with the attack timing.

![ssh 1](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/ssh%201.png)

![ssh 2](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/ssh%202.png)

![ssh 3](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/ssh%203.png)

![ssh 4](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/ssh%204.png)

![ssh 5](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/ssh%205.png)

### 5 Configure Active Response for IP Blocking
Active Response allows Wazuh to automatically block malicious IP addresses based on configured detections (e.g., SSH brute-force). Configure and test this feature carefully in a lab environment before applying to production.
### Steps to configure Active Response:
### 1. Edit the manager configuration file:
```bash
sudo nano /var/ossec/etc/ossec.conf
```
- Enable the desired active-response module (for example `firewalld` or `iptables`) and define the rule IDs that will trigger the response.
- Add an `<active-response>` entry that maps the command and the rule ID(s) to be blocked.
- Restart or reload the Wazuh manager for changes to take effect:
```bash
sudo systemctl restart wazuh-manager
```
**Example Active Response snippet (block SSH brute-force):**
```xml
<active-response>
  <command>firewalld-drop</command>
  <location>any</location>
  <rules_id>5716</rules_id> <!-- SSH brute force -->
</active-response>
```
### Notes:
- Test active-response rules in an isolated lab to avoid accidental blocking of legitimate IPs.
- If using `iptables` or `firewalld`, ensure the manager has the appropriate permissions and that the command exists and is properly configured on the target host.
- Document each active-response rule with a rationale and expected behavior for auditability.

# Lab 3: Vulnerability Detection
### Configuration on Wazuh Server
### 1. **Enable Vulnerability Detection** in the Wazuh manager configuration file (`/var/ossec/etc/ossec.conf`):
```xml
<vulnerability-detection>
   <enabled>yes</enabled>
   <index-status>yes</index-status>
   <feed-update-interval>60m</feed-update-interval>
</vulnerability-detection>
```
### 2. **Configure the Wazuh indexer** by specifying the correct IP/hostname in the `<indexer>` section:
```xml
<indexer>
  <enabled>yes</enabled>
  <hosts>
    <host>https://<your_indexer_ip>:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/etc/filebeat/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>/etc/filebeat/certs/filebeat.pem</certificate>
    <key>/etc/filebeat/certs/filebeat-key.pem</key>
  </ssl>
</indexer>
```
### 3. **Restart the Wazuh Manager** to apply the configuration changes:
```basah
sudo systemctl restart wazuh-manager
```

![vulnerability detection 1](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/vulnerability%20detection%201.png)

![vulnerability detection 2](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/vulnerability%20detection%202.png)

![vulnerability detection 3](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/vulnerability%20detection%203.png)

![vulnerability detection 4](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/vulnerability%20detection%204.png)

# Lab 4: Detecting Suspicious Binaries with Wazuh Rootcheck
### Overview
Wazuh’s **rootcheck** module (agent-side) detects suspicious or trojanized binaries, rootkits, hidden processes, unexpected ports, and anomalous files on endpoints (e.g., Ubuntu). This lab demonstrates configuring Rootcheck, simulating a trojanized binary, and verifying detection through the Wazuh manager dashboard.
### Agent Configuration (Ubuntu)
On the monitored endpoint, ensure the Rootcheck configuration in `/var/ossec/etc/ossec.conf` contains the following:
```xml
<rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency> <!-- Every 12 hours -->
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
</rootcheck>
```
Note: By default Rootcheck is enabled. Adjust the `<frequency>` value if you require more frequent scans in a lab environment.
### Attack Simulation (Agent)
### 1. Create a backup of the original binary:
```bash
sudo cp -p /usr/bin/w /usr/bin/w.copy
```
### 2. Replace the binary with a trojanized script (simulated trojan):
```bash
sudo tee /usr/bin/w << 'EOF'
#!/bin/bash
echo "`date` this is evil" > /tmp/trojan_created_file
echo 'test for /usr/bin/w trojaned file' >> /tmp/trojan_created_file
/usr/bin/w.copy
EOF
sudo chmod +x /usr/bin/w
```
Warning: Perform this only in an isolated lab. Do not run trojanized binaries on production systems.
### Force Immediate Detection
Rootcheck runs on its configured schedule (default: every 12 hours). To trigger an immediate scan and generate events:
```bash
sudo systemctl restart wazuh-agent
```
You can also inspect agent logs for immediate evidence:
```bash
sudo tail -f /var/ossec/logs/ossec.log
```
### Verify Detection on the Manager / Dashboard
On the Wazuh manager dashboard:

1. Open **Threat Hunting** (or the equivalent Alerts/Events view).
2. Apply a filter to locate Rootcheck events, for example:
```pgsql
location:rootcheck AND rule.id:510 AND data.title:"Trojaned version of file detected."
```
3. Optionally view `full_log` or raw event data for contextual evidence (file paths, checksums, timestamps).


![binary 1](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/binary%201.png)

![binary 2](https://raw.githubusercontent.com/Cr4xen/SIEM-Home-Lab-for-Log-Analysis-Threat-Detection-and-Incident-Response/main/Images/binary%202.png)

# Lab 5: Detecting and Removing Malware Using VirusTotal Integration
### Overview
This lab demonstrates integrating Wazuh with **VirusTotal** to automatically scan and remove malicious files. The File Integrity Monitoring (FIM) module triggers alerts when monitored files change or are added. An active-response script (`remove-threat.sh`) deletes files flagged as malicious by VirusTotal.
### Prerequisites
- Functional Wazuh manager and agent setup.
- VirusTotal API key ([get one here](https://developers.virustotal.com/reference/getting-started])
- `jq` utility installed on the endpoint for JSON parsing.
### 1. Agent Configuration (Ubuntu Example)
### a). Enable and Configure FIM
Edit the agent configuration file (`/var/ossec/etc/ossec.conf`):
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>
  <alert_new_files>yes</alert_new_files>
  <directories realtime="yes">/root</directories>
</syscheck>
```
### b). Install `jq` Utility
```bash
sudo apt update
sudo apt -y install jq
```
### c). Create the Active Response Script
Create the script at `/var/ossec/active-response/bin/remove-threat.sh`:
```bash
#!/bin/bash
LOCAL=`dirname $0`
cd $LOCAL
cd ../
PWD=`pwd`
read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
LOG_FILE="${PWD}/../logs/active-responses.log"

if [ ${COMMAND} = "add" ]; then
  printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'
  read RESPONSE
  COMMAND2=$(echo $RESPONSE | jq -r .command)
  if [ ${COMMAND2} != "continue" ]; then
    echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
    exit 0
  fi
fi

rm -f $FILENAME
if [ $? -eq 0 ]; then
  echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
else
  echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat" >> ${LOG_FILE}
fi

exit 0
```
Set script permissions:
```bash
sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh
```
Restart the agent:
```bash
sudo systemctl restart wazuh-agent
```
### 2. Manager Configuration
### a). Create or Update Local Rules
Edit `/var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7">
  <rule id="100200" level="7">
    <if_sid>550</if_sid>
    <field name="file">/root</field>
    <description>File modified in /root directory.</description>
  </rule>
  <rule id="100201" level="7">
    <if_sid>554</if_sid>
    <field name="file">/root</field>
    <description>File added to /root directory.</description>
  </rule>
</group>

<group name="virustotal">
  <rule id="100092" level="12">
    <if_sid>657</if_sid>
    <match>Successfully removed threat</match>
    <description>Active Response successfully removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Active Response error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
```
### b). Configure Integration and Active Response
Add the following to `/var/ossec/etc/ossec.conf`:
```xml
<command>
  <name>remove-threat</name>
  <executable>remove-threat.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>remove-threat</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>

<integration>
  <name>virustotal</name>
  <api_key>YOUR_VIRUSTOTAL_API_KEY</api_key>
  <rule_id>100200,100201</rule_id>
  <alert_format>json</alert_format>
</integration>
```
Replace `YOUR_VIRUSTOTAL_API_KEY` with your actual VirusTotal API key.

Restart the Wazuh manager:
```bash
sudo systemctl restart wazuh-manager
```
### 3. Testing (Malware Emulation)
Download the EICAR test file:
```bash
sudo curl -Lo /root/eicar.com https://secure.eicar.org/eicar.com
sudo ls -lah /root/eicar.com
```
The FIM module will detect the new file, query VirusTotal, and trigger the active-response script to remove it automatically.
### 4. Visualize Alerts in Wazuh Dashboard
- Navigate to **Threat Hunting** in the Wazuh dashboard.
- Apply the following filter:
```text
rule.id: 553,100092,87105,100201
```
You should see:
- Alert for file added (`100201`)
- VirusTotal detection
- Active-response execution (`100092`/`87105`)

# Challenges Faced
During the initial Wazuh environment setup, I encountered a **log visibility issue** where event logs were **not being generated or displayed** on the Wazuh dashboard. This prevented real-time monitoring and analysis of system activities, creating a temporary loss of visibility across the managed endpoint.

After identifying the issue, I performed targeted troubleshooting — verifying agent-to-manager connectivity, inspecting service statuses, and reviewing configuration paths within `ossec.conf`. The root cause was related to a configuration mismatch that prevented log events from being forwarded correctly. Once corrected and the services were restarted, the event flow was successfully restored, and logs began to appear as expected in the dashboard.

# Key Learnings
Through this activity, I gained practical experience in **real-time log monitoring and analysis** using the Wazuh dashboard. I learned how to **view, interpret, and correlate security events** effectively to understand endpoint behavior and detect anomalies.

Additionally, I developed a deeper understanding of how to **integrate security tools** within a monitoring environment, as well as how to **configure and fine-tune detection rules** to improve alert accuracy and system responsiveness.

This process significantly enhanced my **problem-solving and troubleshooting skills** — especially in identifying and resolving issues related to event visibility and data flow. I also learned how to **approach technical challenges systematically**, maintaining focus under pressure and ensuring that critical issues are addressed methodically rather than reactively.

Overall, this experience strengthened both my **technical proficiency** and **analytical mindset**, key competencies for any cybersecurity professional responsible for maintaining visibility, integrity, and resilience across security operations.

---
