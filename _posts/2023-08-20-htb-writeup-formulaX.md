---
layout: single
title: FormulaX - Hack The Box
excerpt: "Descripcion"
date: 2024-03-10
classes: wide
header:
  teaser: assets/images/htb-writeup-formulax/logo.PNG
  teaser_home_page: true
  icon: assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Box
  - mongoDB
  - xss
  - csrf
---

![](../assets/images/htb-writeup-formulax/FormulaXTeaser.png)

**RECON**

**PORTS SCAN**

```ruby
sudo nmap -p- -sS --open --min-rate 5000 -Pn -n -vvv 10.129.188.227 -oG allPorts
[sudo] password for anonimo: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-10 12:55 CET
Initiating SYN Stealth Scan at 12:55
Scanning 10.129.188.227 [65535 ports]
Discovered open port 22/tcp on 10.129.188.227
Discovered open port 80/tcp on 10.129.188.227
Completed SYN Stealth Scan at 12:55, 14.58s elapsed (65535 total ports)
Nmap scan report for 10.129.188.227
Host is up, received user-set (0.11s latency).
Scanned at 2024-03-10 12:55:40 CET for 15s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.72 seconds
           Raw packets sent: 72314 (3.182MB) | Rcvd: 71754 (2.870MB)
```

**SERVICE AND VERSION SCAN**

```ruby

❯ sudo nmap -p22,80 -sCV 10.129.188.227 -oN target
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-10 12:58 CET
Nmap scan report for 10.129.188.227
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 5f:b2:cd:54:e4:47:d1:0e:9e:81:35:92:3c:d6:a3:cb (ECDSA)
|_  256 b9:f0:0d:dc:05:7b:fa:fb:91:e6:d0:b4:59:e6:db:88 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-cors: GET POST
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was /static/index.html
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.95 seconds

```
