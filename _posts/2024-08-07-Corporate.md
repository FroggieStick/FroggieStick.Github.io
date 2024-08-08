---
layout: post
title:  Corporate
description: Corporate is an insane-difficulty Linux machine featuring a feature-rich web attack surface that requires chaining various vulnerabilities to bypass strict Content Security Policies (CSP) and steal an authentication cookie via Cross-Site Scripting (XSS). ...
date:   2024-08-07 16:03:00 -0500
image:  '/images/corporate01.jpg'
tags:   [HackTheBox, CTF, Retired, Windows, Insane]
---
# Machine Info

<blockquote>
Corporate is an insane-difficulty Linux machine featuring a feature-rich web attack surface that requires chaining various vulnerabilities to bypass strict Content Security Policies (CSP) and steal an authentication cookie via Cross-Site Scripting (XSS). This results in staff-level access to internal web applications, from where a file-sharing service's access controls can be bypassed to access other users files. This leads to an onboarding document revealing the default password template. Password spraying the SSO endpoint returns valid credentials, which can be used to SSH into a workstation that authenticates via LDAP. Data in the users home directory can be used to brute force the pin to a Bitwarden vault, enabling the attacker to pass multi-factor authentication (MFA) on Gitea and enumerate private repositories, discovering a private key used to sign JWT tokens. Forging a token and authenticating as a user in the engineering group, the LDAP password is changed to obtain system access to the group and a docker socket, which is leveraged to obtain `root` privileges inside a `Proxmox` environment. The container is escaped using a private SSH key belonging to the sysadmin group. Finally, [CVE-2022-35508](https://nvd.nist.gov/vuln/detail/CVE-2022-35508) is used to exploit PVE and obtain access to the `root` account on the host machine. 
</blockquote>

##### Rating: Insane ; Platform: Linux

# Reconnaissance
##### Nmapping: {% highlight markdown %} nmap -sC -sV -A BoxIpAddress > CorporateNmap.txt {% endhighlight %}

{% highlight markdown %}
PORT   STATE SERVICE VERSION
80/tcp open  http    OpenResty web app server 1.21.4.3
|_http-title: Corporate.HTB
{% endhighlight %}

It appears we have only one port worth looking into. There is a web server running offering up a website on port 80.
* The title of the website is: Corporate.HTB

##### Ffufing:
{% highlight markdown %}
 ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt  -u http://corporate.htb -H 'Host: FUZZ.corporate.htb' -fs 175
 {% endhighlight %}
 <b>Subdomains:</b>
* support.corporate.htb
* git.corporate.htb
* sso.corporate.htb
* people.corporate.htb

Lets add these subdomains to your <mark>/etc/hosts</mark> file.

##### 🐸 Web Exploration: 
After poking around the main site some we find a chat bot. It appears to be located at the <a href="http://support.corporate.htb"></a> subdomain.

We are able to send some "html" scripts to the bot and it relays them back to us. It appears this bot maybe vulnerable to some <bold>XSS Injection</bold>.
After attempting some scripts I noticed that the bot is parsing javascript. We attempt some simple javascript xss but looking at the response we notice that the scirpts are being blocked by <bold>CSA</bold> or Content-Secutiry-Policy.
You can read more about CSA here <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"></a>.

<blockquote>Testing another block quote. I wonder how this will look.</blockquote>