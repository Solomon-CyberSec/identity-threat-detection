# Identity Threat Detection

Identity is the new perimeter. Most breaches today start with a compromised account, not a firewall bypass. This repo has SPL queries and detection playbooks specifically for catching identity-based threats — in both on-prem Active Directory and Azure AD / Entra ID.

Built from hands-on experience investigating account compromises, privilege escalations, and insider threats in enterprise environments.

---

## Detections Included

| Detection | Platform | MITRE Technique | Severity | Status |
|-----------|----------|-----------------|----------|--------|
| Password Spray Attack | AD / Entra ID | T1110.003 | High | ✅ |
| Impossible Travel Login | Entra ID | T1078 | High | ✅ |
| MFA Fatigue / Push Spam | Entra ID | T1621 | High | ✅ |
| New Global Admin Assigned | Entra ID | T1098.003 | Critical | ✅ |
| Service Account Login Outside Hours | AD | T1078.002 | Medium | ✅ |
| User Added to Privileged Group | AD | T1098.007 | High | ✅ |
| Stale Account Suddenly Active | AD / Entra ID | T1078 | Medium | ✅ |
| Kerberoasting Indicator | AD | T1558.003 | High | ✅ |
| Pass-the-Hash Detected | AD | T1550.002 | Critical | ✅ |
| OAuth App Granted High Permissions | Entra ID | T1528 | High | ✅ |

---

## Why Identity Detection Matters

Once an attacker has valid credentials, most security tools go quiet — because everything looks like a legitimate user. The detections in this repo are designed to catch the behavior that gives attackers away even when they're using real credentials:

- Logging in from unusual locations or at unusual times
- Escalating privileges quietly
- Moving laterally using credential theft techniques
- Abusing service accounts and OAuth apps

---

## Repo Layout

```
identity-threat-detection/
├── README.md
├── active-directory/
│   ├── kerberoasting.spl
│   ├── pass-the-hash.spl
│   ├── privileged-group-change.spl
│   └── service-account-anomaly.spl
├── entra-id/
│   ├── password-spray.spl
│   ├── impossible-travel.spl
│   ├── mfa-fatigue.spl
│   ├── new-global-admin.spl
│   └── oauth-app-permissions.spl
├── playbooks/
│   ├── account-compromise-response.md
│   └── privilege-escalation-response.md
└── docs/
    └── identity-attack-patterns.md
```

---

## Sample Queries

### Password Spray Detection
> **Tactic:** Credential Access | **Technique:** T1110.003

Password spraying hits many accounts with the same common password. Unlike brute force, it stays under lockout thresholds. The tell is lots of failed logins spread across many different accounts from the same source IP.

```spl
index=azure sourcetype=azure:aad:signin ResultType=50126
| bucket _time span=10m
| stats dc(UserPrincipalName) as accounts_targeted, count as total_attempts by _time, IPAddress
| where accounts_targeted >= 10 AND total_attempts >= 20
| sort - accounts_targeted
| rename IPAddress as "Source IP", accounts_targeted as "Accounts Targeted"
```

---

### Kerberoasting Detection
> **Tactic:** Credential Access | **Technique:** T1558.003

Kerberoasting requests service tickets for accounts with SPNs so the attacker can crack them offline. A spike in TGS requests — especially for service accounts — is a strong indicator.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4769
| where TicketEncryptionType="0x17"
| stats count as ticket_requests by src_user, ServiceName, src_ip, _time
| where ticket_requests > 5
| sort - ticket_requests
| rename src_user as "Requesting User", ServiceName as "Target Service"
```

---

### Stale Account Suddenly Active
> **Tactic:** Initial Access | **Technique:** T1078

Accounts that haven't logged in for 90+ days suddenly becoming active is worth investigating. Could be a forgotten account being abused, or a credential that was quietly stolen and is now being used.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624
| stats latest(_time) as last_login, earliest(_time) as first_login by user
| eval days_inactive = round((now() - last_login) / 86400, 0)
| where days_inactive > 90
| sort - days_inactive
| rename user as "Account", days_inactive as "Days Inactive"
```

---

### New Global Admin Assigned
> **Tactic:** Privilege Escalation | **Technique:** T1098.003

Any change to Global Admin membership should be treated as a high-priority event. This query catches role assignments in Entra ID the moment they happen.

```spl
index=azure sourcetype=azure:aad:audit OperationName="Add member to role"
| search TargetResources{}.modifiedProperties{}.newValue="*Global Administrator*"
| stats count by InitiatedBy.user.userPrincipalName, TargetResources{}.userPrincipalName, _time
| sort - _time
| rename InitiatedBy.user.userPrincipalName as "Added By", TargetResources{}.userPrincipalName as "New Admin"
```

---

### OAuth App Granted High Permissions
> **Tactic:** Persistence | **Technique:** T1528

Attackers sometimes get users to grant OAuth apps excessive permissions so they can access email, files, or calendars persistently without needing the user's password. This query catches high-risk permission grants.

```spl
index=azure sourcetype=azure:aad:audit OperationName="Consent to application"
| search Target{}.modifiedProperties{}.newValue="*Mail.ReadWrite*" OR Target{}.modifiedProperties{}.newValue="*Files.ReadWrite.All*"
| stats count by InitiatedBy.user.userPrincipalName, Target{}.displayName, _time
| sort - _time
```

---

## Tools & Environment

- **Splunk Enterprise / Splunk Cloud** — detection platform
- **Microsoft Entra ID / Azure AD** — cloud identity logs
- **Windows Active Directory** — on-prem identity logs
- **MITRE ATT&CK v14** — tactic and technique mapping
- **Log sources:** Azure AD Sign-in, Audit logs, Windows Security Events

---

## About

10 years in IT, 6 years in cybersecurity (network security, SIEM engineering, SOC operations). MS in Information Systems, CCNP Security.

Part of a broader portfolio covering threat detection, incident response, and security automation.

> GitHub: [Solomon-CyberSec](https://github.com/Solomon-CyberSec)
