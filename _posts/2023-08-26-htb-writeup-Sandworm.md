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

**NMAP**

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
