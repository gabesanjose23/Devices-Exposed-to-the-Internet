
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

### 2. Find out if anyone has attempted to login into the machine

Several bad actor have been discovered attempting to login into the Target machine.

**Query used to locate event:**

```kql
DeviceLogonEvents
|where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
<img width="1212" alt="image" src="Screenshot 2025-03-10 141537.png">

---

### 3. Check if any of the bad actor where able to login

The top 10 most failed login attempts IP addresses have not been able to successfully break into the VM

**Query used to locate events:**

```kql
let RemoteIPsInQuestion = dynamic(["128.1.44.9", "178.20.129.235", "83.118.125.238", "106.246.239.179", "85.215.149.156", "146.196.63.17", "89.232.41.74", "190.5.100.193", "178.176.229.228"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
<img width="1212" alt="image" src="Screenshot 2025-03-10 143007.png">

---

### 4. Check who dose have access to the account

The only successful remote/network logons in the last 7 days was for the ‘labuser’ account (6 total)

**Query used to locate events:**

```kql
DeviceLogonEvents
| where LogonType =="Network"
| where ActionType == "LogonSuccess"
|where DeviceName =="windows-target-1"
|where AccountName == ”labuser”
```
<img width="1212" alt="image" src="Screenshot 2025-03-10 145153.png">

---
### 5. Check if labuser has any suspicious failed login attemps 

There were (0) failed logons for the ‘labuser’ account,indicating that a brute force attempts for this account didn’t take place,and a 1-time password guess is unlikely.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where LogonType =="Network"
| where ActionType == "LogonFailed"
|where DeviceName =="windows-target-1"
|where AccountName == "labuser"
```
<img width="1212" alt="image" src="Screenshot 2025-03-10 145659.png">

---

### 6. Check if the location from which is being logon from is normal

We checked all of the successful login IP addresses for the “labuser” account to see if any of them were unusual or from an unexpected location,All were normal.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where LogonType =="Network"
| where ActionType == "LogonSuccess" 
|where DeviceName =="windows-target-1"
|where AccountName == "labuser"
| summarize loginCount = count() by DeviceName,ActionType,AccountName,RemoteIP
```
<img width="1212" alt="image" src="Screenshot 2025-03-10 150405.png">

---

## Summary

Though the device was exposed to the internet and clear brute force attempts have taken place, there is no evidence of any brute force success or unauthorized access from the legitimate account “labuser”.

MITRE ATT&CK - T1190: Exploit Public-Facing Application

MITRE ATT&CK - T1078: Valid Accounts

MITRE ATT&CK - T1110: Brute Force

---

## Response Action

--Hardened the NSG attached to “windows-target-1” to allow only RDP traffic from specific end-points(no public internet access)

--Implemented account lockout policy

--Implement MFA


---
