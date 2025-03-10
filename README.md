
# Devices Exposed to the Internet scenario


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.
---
##  Hypothesis based on threat intelligence and security gaps

During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts.


## Steps Taken

### 1. Find out how long it's been exposed to the internet 

Windows-target-1 has been internet facing for several days.Last internet facing time: 2025-03-10T18:28:06.2983018Z

**Query used to locate events:**

```kql
DeviceInfo
| where DeviceName == "windows-target-1"
|where IsInternetFacing == true
| order by Timestamp desc

```
<img width="1212" alt="image" src="Screenshot 2025-03-10 140735.png">

---

### 2. Find out how many people attempted to login into the machine

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.7.exe". Based on the logs returned, at `2025-03-08T19:26:59.3952232Z`, an employee on the "threat-hunt-gsl" device ran the file 'tor-browser-windows-x86_64-portable-14.0.7.exe' from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-gsl"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="Screenshot 2025-03-08 173554.png">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-03-08T19:37:03.5825892Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-gsl"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="Screenshot 2025-03-08 174728.png">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-08T19:38:13.127864Z`, an employee on the "threat-hunt-gsl" device successfully established a connection to the remote IP address `127.0.0.1` on port `9150`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-gsl"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="Screenshot 2025-03-08 175554.png">

---

## Summary

Though the device was exposed to the internet and clear brute force attempts have taken place, there is no evidence of any brute force success or unauthorized access from the legitimate account “labuser”

MITRE ATT&CK - T1190: Exploit Public-Facing Application

MITRE ATT&CK - T1078: Valid Accounts

MITRE ATT&CK - T1110: Brute Force

---

## Response Action

--Hardened the NSG attached to “windows-target-1” to allow only RDP traffic from specific end-points(no public internet access)

--Implemented account lockout policy

--Implement MFA


---
