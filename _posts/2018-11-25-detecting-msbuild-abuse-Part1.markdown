---
layout: single
title:  "Detecting MSBuild.exe Abuse (Part 1)"
date:   2018-11-25 11:47:14 +0000
categories:
---

MSBuild is a technique discovered by Casey Smith ([@SubTee](https://twitter.com/subTee)) to execute code and bypass applocker, device guard or other whitelisting solutions. It's great for executing 1st stage payloads then performing more advanced injection techniques for (almost) diskless implants and C2.

This post walks through some methods for detection, and advice on how to test and document it in an enterprise environment. In part one we will setup an environment to perform some simple tests, generate log entries and begin creating our detection strategy. Then in part two we'll investigate some more advanced usages of MSbuild and refine our use cases.

The steps for part one are as follows.

1. Setup a test Windows 7 system using FlareVM
2. Install Sysmon using the [@SwiftOnSecurity](https://twitter.com/SwiftOnSecurity) config and configure Windows event logging
3. Install Atomic Red Team to help us perform a repeatable red team test scenario
4. Run atomic test T1127 to generate some Sysmon log data
5. Review the log data and identify patterns
6. Run Sigma to generate some inital SIEM use cases
7. Use the Palantir Alerting and Detection Framework to create some draft use case documentation

And we will be using the following tools.

- A Windows 7 [FlareVM](https://www.fireeye.com/blog/threat-research/2018/11/flare-vm-update.html) for testing
- Microsoft [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) and [@SwiftOnSecurity](https://twitter.com/SwiftOnSecurity/status/827692148745175040)'s Sysmon configuration
- Bonus: Carbon Black Response (Other EDR tools are available!)
- Red Canary's [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) testing framework
- Florian Roth's ([@cyb3rops](https://twitter.com/cyb3rops)) SIEM use case generator [Sigma](https://github.com/Neo23x0/sigma)
- [Splunk](https://www.splunk.com/en_us/download.html) or your preferred SIEM solution
- Palantir's [Alerting and Detection Framework](https://github.com/palantir/alerting-detection-strategy-framework)

Now lets get started!

# MSBuild Technique Overview

Casey's blog is no longer available however you can find the original article on the [Wayback Machine](https://web.archive.org/web/20161212224652/http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html) and a quick google will find many other examples of offensive usage.

>I found a Microsoft signed tool called MSBuild.exe. This is a default .NET utility that ships with Windows. I usually start with the question; ‘HOW could I get MSbuild to execute code for me?’.
>
>Turns out, MSBuild.exe has a built in capability called “Inline Tasks”.  These are snippets of C# code that can be used to enrich the C# build process.  Essentially, what this does, is take an XML file, compile and execute in memory on the target, so it is not a traditional image/module execution event.

# Installing FlareVM 

FlareVM is designed to quickly setup a Windows 7 based malware analysis VM but it also an excellent base package for a general security research. Think of it a little like Kali for Windows.

Personally I have a semi-permanent FlareVM for research or CTF's using a valid license key and other temporary FlareVM's using a trial Windows version for malware analysis.

If you don't have a valid license key then Microsoft offer pre-built images for testing purposes that can be used.

1. Make sure you have a way of setting up a virtual environment such as VMware or VirtualBox. If you're unsure how to do this checkout [@da_667](https://twitter.com/da_667) who has excellent resources on setting up virtual lab environments
2. Download and install IE11 on Win 7 (x86) from Microsoft <https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/>
3. Follow the instructions to install FlareVM <https://www.fireeye.com/blog/threat-research/2018/11/flare-vm-update.html>
4. **Note** when running install.ps1 just hit enter when asked for a password, the IEUser autologin is already configured in the image

We're also going to want to install a few extras such as git and the Windows 7 remote administration tools (RSAT) so lets do that now. Installing tools using the Chocolatey package manager setup by FlareVM is as simple as opening an admin cmd or powershell window and typing the below.

`choco install git`

`choco install rsat`

# Sysmon and Windows Event Logging

Detecting these sorts of attacks on Windows is not possible out the box and having process logging is essential. Windows can be configured to perform rudimentary process logging but Sysmon or an EDR solution should be considered mandatory in any enterprise environment. We'll look at both outputs to compare and see how Sysmon and EDR tools can help create much higher fidelity detections.

1. Download sysmon <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
2. Clone the sysmon config with `git clone https://github.com/SwiftOnSecurity/sysmon-config.git`
3. Open an admin cmd or powershell window and configure Sysmon using `sysmon.exe -accepteula -i sysmonconfig-export.xml`

We will also want to configure Windows [Event ID 4688](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688) which is turned off by default but does enable Windows to log process events without the need for Sysmon.

1. Using the RSAT tools installed previously open "Local Security Policy" admin mmc
2. Navigate to `Local Policies -> Audit Policy -> Audit Process Tracking`
3. Edit Audit Process Tracking to enable "Success"

# Atomic Red Team



# Executing the T1127 Test

# Reviewing Windows Logs

# Installing Sigma

# Using Sigma to Generate SIEM Use Cases

# Creating Alerting & Detection Documentation

# Summary

We've now got a detection in place for this dangerous technique and also started building a robust, repeatable, enterprise ready framework for all our blue team detection use cases going forward.

Detecting MSBuild.exe Abuse (Part 2) will build on this to refine the detection logic and review common false positives.