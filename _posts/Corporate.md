---
layout: post
title:  Corporate
description: Corporate is an insane-difficulty Linux machine featuring a feature-rich web attack surface that requires chaining various vulnerabilities to bypass strict Content Security Policies (CSP) and steal an authentication cookie via Cross-Site Scripting (XSS). This results in staff-level access to internal web applications, from where a file-sharing service&amp;#039;s access controls can be bypassed to access other users&amp;#039; files. This leads to an onboarding document revealing the default password template. Password spraying the SSO endpoint returns valid credentials, which can be used to SSH into a workstation that authenticates via LDAP. Data in the user&amp;#039;s home directory can be used to brute force the pin to a Bitwarden vault, enabling the attacker to pass multi-factor authentication (MFA) on Gitea and enumerate private repositories, discovering a private key used to sign JWT tokens. Forging a token and authenticating as a user in the engineering group, the LDAP password is changed to obtain system access to the group and a docker socket, which is leveraged to obtain `root` privileges inside a `Proxmox` environment. The container is escaped using a private SSH key belonging to the sysadmin group. Finally, [CVE-2022-35508](https://nvd.nist.gov/vuln/detail/CVE-2022-35508) is used to exploit PVE and obtain access to the `root` account on the host machine.
date:   2024-08-7 16:03:00 +0500
image:  '/images/corporate01.jpg'
tags:   [retired, Insane]
---
# Nmap:
Testing this test