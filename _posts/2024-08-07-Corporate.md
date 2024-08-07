---
layout: post
title:  Corporate
description: Corporate is an insane-difficulty Linux machine featuring a feature-rich web attack surface that requires chaining various vulnerabilities to bypass strict Content Security Policies (CSP) and steal an authentication cookie via Cross-Site Scripting (XSS). ...
date:   2024-08-07 16:03:00 -0500
image:  '/images/corporate01.jpg'
tags:   [retired, Insane]
featured: true
---
### Nmap:
* [4] nmap -sC -sV -A 10.129.229.168 > corpmap

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-23 07:04 CDT
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.50% done
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 2.65% done; ETC: 07:05 (0:00:37 remaining)
┌─[us-dedivip-1]─[10.10.14.103]─[froggiedrinks@htb-balm1hxe0f]─[~]
└──╼ [★]$ nmap -sC -sV -A 10.129.229.168 > corpmap
┌─[us-dedivip-1]─[10.10.14.103]─[froggiedrinks@htb-balm1hxe0f]─[~]
└──╼ [★]$ cat corpmap 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-23 07:25 CDT
Nmap scan report for corporate.htb (10.129.229.168)
Host is up (0.0084s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    OpenResty web app server 1.21.4.3
|_http-title: Corporate.HTB
|_http-server-header: openresty/1.21.4.3
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|storage-misc
Running (JUST GUESSING): Linux 5.X|4.X|2.6.X (94%), Crestron 2-Series (86%), HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:5.0 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 5.0 (94%), Linux 5.0 - 5.4 (90%), Linux 4.15 - 5.8 (88%), Linux 5.3 - 5.4 (88%), Linux 2.6.32 (87%), Linux 5.0 - 5.5 (87%), Crestron XPanel control system (86%), HP P2000 G3 NAS device (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   8.08 ms 10.10.14.1
2   8.34 ms corporate.htb (10.129.229.168)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.34 seconds
```


# Success!
* This appears to be the foothold path.