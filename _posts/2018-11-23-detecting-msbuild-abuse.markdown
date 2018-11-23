---
layout: post
title:  "Detecting MSBuild Abuse"
date:   2018-11-23 20:47:14 +0000
categories:
---

MSBuild.exe is a valid signed Microsoft binary and is used to allow developers to compile .Net code on machines without Visual Studio. Like many high powered developer or admin utilities it can be seriously misused. In isolation it's not malicous, but the output certianly can be. 

MSBuild is a common technique to execute code on locked down systems and bypassing applocker or other whitelisting solutions. It's great for executing 1st stage payloads and performing more advanced injection techniques for diskless implants and C2.

Detection can be challenging without endpoint process monitoring via Sysmon or an EDR tool. With some careful whitelisting reasonably high fidelity detections should be achivable.

# MSBuild Technique Overview

Here

# Common Legitimate Use Cases

here

#  Detection Techniques

here

# Prevention

# Response

# Blind Spots