---
type: post
title: "Hack the Box Lame Write-up"
date: 2020-05-11 20:27:00 +1000
---
Welcome to the first in this series of write-ups of "OSCP-like" boxes as inspired by TJNull's great article about [OSCP preparation.](https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html)

The OSCP certification is a hands-on exam. With the requirement to hack multiple boxes in the exam lab and produce a detailed pentesting report it relies heavily on real world skills. To begin we will be hacking Lame from <https://hackthebox.eu> and because this is a retired box, we are allowed to post public solutions.

## Overview

![Lame information image](/assets/img/htb-lame-info.png){: .align-right}

Lame is an easy Linux based box from HTB and was one of the earliest that went live. It is a very easy box but also a great example of how powerful some RCE vulnerabilities can be, especially in core networking services like SMB and Samba!

Skills tested:

- Port scanning
- Service enumeration
- Vulnerability CVE identification
- Vulnerability exploitation

## Scanning and Enumeration

Lets start with an [IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) inspired nmap scan using the options `nmap -sC -sV -oA nmap/lame 10.10.10.3` which will give us a good idea of what's on the box.

Nmap options explained:

- `-sC` runs the [default nmap scripts](https://nmap.org/nsedoc/categories/default.html) and provides extra information on many commonly seen services
- `-sV` performs service version detection
- `-oA` exports the output to text, grepable and xml formats
- I do *not* use `-O` or `-A` because I find OS detection unreliable and it is usually more accurate to use the service versions

Breaking down the nmap results gives us the following services that we can investigate in more depth

### Port 21 VSFTPD 2.3.4

```text
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.19
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
```

The nmap option `-sC` already ran the default ftp-anon.nse script for us and we can see that that the FTP allows for anonymous access. Nmap has also identified the version as vsftpd 2.3.4

This FTP server does not contain any interesting files but vsftpd 2.3.4 is vulnerable to a backdoor command injection. Running `searchsploit vsftpd 2.3.4` will find a Metasploit module for this!

![Searchsploit for vsftpd 2.3.4](/assets/img/searchsploit-vsftpd.png){: .align-center}

We could also google the service and version to arrive at the Rapid7 metasploit module documentation.

<https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor>

![Google results for vsftpd 2.3.4](/assets/img/vsftpd-google.png){: .align-center}

### Port 22 OpenSSH 4.7p1

```text
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
```

There are SSH vulnerabilities, but remote code execution is rare and SSH is usually reasonably hardened. Password spraying and stuffing are common techniques used by threat actors in real life but it's not as successful against CTF machines, so we will skip attacking SSH directly.

However, SSH banners can often disclose information about the Linux version. After a bit of googling we can discover that it's Ubuntu "Hardy Heron" 8.04 from 2008

### Port 139 and 445 Samba 3.0.20

```text
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Host script results:
|_clock-skew: mean: -3d00h55m45s, deviation: 2h49m45s, median: -3d02h55m47s
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name:
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2020-05-08T08:30:29-04:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

SMB is a very popular target, both Windows and Linux have remote code execution vulnerabilities and misconfigurations are a common method for gaining a foothold or exposing sensitive information.

Enumeration of SMB using `enum4linux -a 10.10.10.3` and `smbclient -L \\10.10.10.3` usually provides interesting results.

**Unfortunately, at the time of writing, the virtual machine clock is out of sync and this means that SMB can fail to connect with the error *protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED* resulting in difficulty enumerating further**

We can continue our enumeration by searching <https://exploit-db.com> for Samba 3.0.20 and find another Metasploit module. This time for a "Username map script Command Execution" vulnerability which looks promising.

![Search results on exploit-db.com](/assets/img/samba-exploit.png){: .align-center}

## Exploitation

Our scanning and enumeration identified two likely paths of attack, both with metasploit modules available. First start the Metasploit database using `systemctl start postgresql.service` then run the metasploit console using `msfconsole` and lets get hacking!

![Metasploit console image](/assets/img/metasploit-console.png){: .align-center}

### VSFTPD Exploitation

Searching for the VSFTPD backdoor with `search vsftpd` displays only one exploit, so lets use that.

```text
msf5 > search vsftpd

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution
```

1. Load the module with `use exploit/unix/ftp/vsftpd_234_backdoor`
2. Check the options by typing `show options`
3. Set the RHOSTS variable to our target with the `set RHOSTS 10.10.10.3` command

![vsftpd exploit setup](/assets/img/vsftpd-msfconsole.png){: .align-center}

Finally, we simply type `exploit` and...

![vsftpd exploit failure](/assets/img/vsftpd-exploit-fail.png){: .align-center}

Unfortunately, we get the "Exploit completed, but no session was created" error message which usually means that the target is not actually vulnerable. Perhaps some naughty CTF creator fixed it without updating the version and left us with a rabbit hole to get stuck in? ;)

That failure does not stop us though, we have more exploits to try!

### Samba Exploitation

Following the same steps as before we can use Metasploit again to try the Samba 3.0.20 username map command execution vulnerability.

1. Type `search Samba` within Metasploit
2. Select the module by typing `use exploit/multi/samba/usermap_script`
3. Set the RHOSTS with `set RHOSTS 10.10.10.3`
4. And `exploit`

This time we should see something much better, a successful command shell where can run Linux commands and we seem to be root!

![successful command shell](/assets/img/samba-exploit-msfconsole.png){: .align-center}

You now have completely rooted this system, so pillage away and grab those user.txt and root.txt flags. Congrats on an awesome hack!
