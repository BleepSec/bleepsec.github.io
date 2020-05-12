---
layout: single
title: "Using Att&ck and Atomic Red Team to Detect MSBuild Abuse (Part 2)"
date: 2018-12-08 13:02:00 +0000
---
Following on from [part 1](https://bleepsec.com/2018/11/26/using-attack-atomic-red-team-part1.html) where we used Mitre Att&ck and Atomic Red Team to perform our attack and generate test log events we're now going to build the detections and documentation.

I will be using Splunk in these examples and a free version that allows 0.5GB/day of logs can be downloaded from [Splunk](https://www.splunk.com/en_us/download/splunk-enterprise.html). Configuration and setup of Splunk is outside the scope of this article but there are plenty of guides available via Google or I highly recommend checking out the book and training course on building a virtual security lab by [@da_667](https://twitter.com/da_667/status/1046788282468773888).

In order to give ourselves a head start we can use [Sigma](https://github.com/Neo23x0/sigma) to help generate SIEM rules for a variety of platforms.

>Sigma is a generic and open signature format that allows you to describe relevant log events in a straight forward manner. The rule format is very flexible, easy to write and applicable to any type of log file. The main purpose of this project is to provide a structured form in which researchers or analysts can describe their once developed detection methods and make them shareable with others.

Let get on with the detecting!

## Installing Sigma and getting started

Installing Sigma is a straight forward git clone procedure similar to the other installs. Creating the rules is equally as simple, we'll walk through the steps and more detailed documentation can be found in the [readme](https://github.com/Neo23x0/sigma/blob/master/README.md).

1. Clone the repo `git clone https://github.com/Neo23x0/sigma.git` then `cd sigma`
2. Python should be already installed by FlareVM, if not install Python3 now
3. From the sigma folder run `pip3 install -r tools/requirements.txt`
4. Next run `python .\tools\sigmac --help` to see our available options

We can now search the sigma rules for a relevant yaml file and use the `sigmac` compiler to output the use case into our preferred format. In this article I'll use Splunk however you can modify the output to be compatible with ArcSight, Qradar, Elasticsearch or even just grep or powershell.

Searching the repo for "MSBuild" brings us to `rules/windows/builtin/win_possible_applocker_bypass.yml` and this is exactly what we're looking for. Take some time to review the full yaml file but I'll highlight the key parts as follows.

As we can see it's tagged with "attack.defense_evasion"

```yaml
action: global
title: Possible Applocker Bypass
description: Detects execution of executables that can be used to bypass Applocker whitelisting
status: experimental
references:
    - https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
    - https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/
author: juju4
tags:
    - attack.defense_evasion
```

Next we can review how the detection is created, there is a list of known exploitable .exe files that can be used as defence evasion techniques and specifically the [T1127](https://attack.mitre.org/techniques/T1127/) MSBuild technique.

The file also described any false positives that may occur. In a large enterprise it's likely the level of false positives may be quite high on any DevOps build servers or certain developer desktops.

```yaml
detection:
    selection:
        CommandLine:
            - '*\msdt.exe*'
            - '*\installutil.exe*'
            - '*\regsvcs.exe*'
            - '*\regasm.exe*'
            - '*\regsvr32.exe*'
            - '*\msbuild.exe*'
            - '*\ieexec.exe*'
            - '*\mshta.exe*'
            # higher risk of false positives
#            - '*\cscript.EXE*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: low
```

Next the file describes the sources that can be used to detect these events. As shown in part 1, both Event ID 4688 new process creation and sysmon can be used and the sigma compiler will generate a rule that will use both.

```yaml
---
# Windows Audit Log
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
---
# Sysmon
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
```

## Using Sigma to generate SIEM use cases

To use Sigma to generate the use cases involves running the sigmac compiler, specifying the SIEM output format, the input yaml file and any other transformations.

Executing `python tools/sigmac -t splunk rules/windows/builtin/win_possible_applocker_bypass.yml` will generate the raw searches however if you copy/paste directly into Splunk (or your preferred SIEM) you may find they don't immediately work. In order to fix this we will need to apply the correct transformations using the Sigma config files.

1. Apply the Splunk Windows field mapping and sourcetypes by adding the `--config tools/config/splunk-windows-all.yml` option
2. Only create the Sysmon rule so we have more control for whitelisting and tuning by adding the `--filter logsource=sysmon` option
3. Output to a file for easier viewing and copy/paste by adding `--output ./T1127.txt`

Our final command and the Splunk rule should look something like the below code snippets, and then searching Splunk should find us some suspicious events!

```text
python tools/sigmac -t splunk rules/windows/builtin/win_possible_applocker_bypass.yml --config .\tools\config\splunk-windows-all.yml --filter logsource=sysmon --output ./T1127.txt
```

```text
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1"
    (CommandLine="*\\msdt.exe*" OR CommandLine="*\\installutil.exe*" OR CommandLine="*\\regsvcs.exe*"
    OR CommandLine="*\\regasm.exe*" OR CommandLine="*\\regsvr32.exe*" OR CommandLine="*\\msbuild.exe*"
    OR CommandLine="*\\ieexec.exe*" OR CommandLine="*\\mshta.exe*"))
```

![Splunk output form search](/assets/img/splunk-t1127-search.png){: .align-center}

## Creating a documentation framework

Documentation is the part everyone hates, but it's the part that is essential in any large enterprise. Good documentation doesn't have to be a huge overhead and it can help drive continual improvement of your use cases, false positives or whitelists. It will even impress the most hardened of auditors!

A clear and effective documentation framework was open sourced by the [Palantir](https://medium.com/@palantir) incident response team. This [Alerting and Detection Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework) makes it simple to link together our Att&ck techniques, Atomic Red Team tests and Sigma use cases into flexible documentation and can be used to help direct our future monitoring and detection strategies.

The ADS framework documents consist of sections on goals and technical context to allow SOC analysts to quickly understand the alert and sections on blind spots, assumptions, false positives and validation to allow for effective investigation and improvement.

There are excellent examples already in the ADS framework repo, and an example for our MSBuild detection can be found below.

[https://github.com/BleepSec/alerting-detection-strategy-framework/blob/msbuild-blog/ADS-Examples/006-MBBuild-Trusted-Dev-Tools-Bypass.md](https://github.com/BleepSec/alerting-detection-strategy-framework/blob/msbuild-blog/ADS-Examples/006-MBBuild-Trusted-Dev-Tools-Bypass.md)

## Summary

With all these pieces now in place we can see how various open source frameworks such as Att&ck, Atomic Red Team, Sigma and Palantir ADS can be used together to create a fully enterprise ready solution for the development, testing and documentation of SIEM use cases.

I look forward to seeing how this can be used by others, happy hunting!
