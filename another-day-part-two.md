# Threat Hunt Report: Another Day, Part Two

**Participant:** Andy Dang
**Date:** May 2026

## Summary
At Nimbus Health, the newly hired IT Support Technician Mason Reed became the target of a single attacker in South Korea.
The attacker used a data breach that provided valid credentials to log in to Reed's account on a single device.
Once in, the attacker exfiltrated a personnel record from the device and left.

## Timeline and Queries

### Reconnaissance
The attacker looked through Nimbus Health's Security Operations Artifacts and identified a target to breach: Mason Reed.
The attacker then found Reed's LinkedIn profile and identified a personal email on the site: mason.reed@hotmail.com.
After that, the attacker found that the email was involved in several breaches, one of which was the Synthient Credential Stuffing Threat Data Breach. That breach was recent and provided cleartext emails and passwords.
With cleartext data from the breach, the attacker obtained Reed's credentials to log in to the IT Workstation.

### Initial Access
The attacker logged in to the device "nh-wks-it-01" on the account "m.reed" initially with the IP address 116.45.242.115, based in South Korea. A subsequent login can be found with the IP address 45.131.194.61, based in California.
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-wks-it-01"
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-30))
| where isnotempty(RemoteIP)
| where AccountName == "m.reed"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, ActionType, RemoteIP
| order by TimeGenerated asc
```
<img width="685" height="309" alt="Screenshot 2026-08-20 164946" src="https://github.com/user-attachments/assets/26fc7b03-7281-4a84-af0e-3e62acd4bbec" />
