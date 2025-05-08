---
title: "Mastering Bash Scripting: From Zero to Automation Hero"
subtitle: "Unlock the power of shell scripting with pro techniques ⚡ "
summary: "Learn Bash scripting from fundamentals to advanced automation with real-world examples, terminal outputs, and pro tips for security and efficiency."
date: 2025-05-08
cardimage: Bash.jpeg
featureimage: Linux.jpeg
caption: Bash
authors:
  - Havoc: Havoc.jpeg
---

## Bash Scripting in Real-Time: Automate Your World

Bash scripting is one of the most powerful skills in a Linux user's toolbox.Bash is the **swiss army knife** of Linux/Mac systems. Want to:  
🔹 Automate repetitive tasks  
🔹 Chain commands like a wizard  
🔹 Process text/data at lightspeed 

"Basic to advanced bash scripting examples"

1️⃣ 𝕊𝕙𝕖𝕓𝕒𝕟𝕘 (#!)

Every script starts with this magic line:

```bash
#!/bin/bash
```
This tells the system: "Run me with Bash!"

2️⃣ 𝔹𝕒𝕤𝕚𝕔 𝕊𝕔𝕣𝕚𝕡𝕥

Create hello.sh:

```bash
#!/bin/bash
echo "🔥 Hello, $(whoami)! Today is $(date)"
```

Run it:

```bash
$ chmod +x hello.sh
$ ./hello.sh
🔥 Hello, kali! Today is Wed May 8 16:45:22 EDT 2025
```


### Real-Time Example 

### 1: Backup Script

Let's say you want to automate backups of a folder:

```bash
#!/bin/bash
SRC="/home/user/documents"
DEST="/home/user/backup"
DATE=$(date +%F)
mkdir -p "$DEST/$DATE"
cp -r "$SRC" "$DEST/$DATE"
echo "Backup completed for $SRC on $DATE"
```

**Run & Output**:

```bash
$ bash backup.sh
Backup completed for /home/user/documents on 2025-05-08
```

### Real-Time Example 

### 2: System Monitoring Script

This script monitors CPU and memory usage:

```bash
#!/bin/bash
echo "System Monitoring Report"
echo "-------------------------"
top -b -n1 | head -n 5
```

**Run & Output**:

```bash
$ bash monitor.sh
System Monitoring Report
-------------------------
top - 08:45:01 up 3 days,  2:41,  1 user,  load average: 0.15, 0.17, 0.14
Tasks: 195 total,   1 running, 194 sleeping,   0 stopped,   0 zombie
%Cpu(s):  3.0 us,  1.0 sy,  0.0 ni, 95.0 id,  1.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   7894.5 total,   1254.2 free,   3540.3 used,   3100.0 buff/cache
```

### Real-Time Example 

### 3: Batch File Renamer

Renames all `.txt` files in a directory to include a timestamp:

```bash
#!/bin/bash
for file in *.txt; do
  mv "$file" "$(date +%Y%m%d)_$file"
done
```

**Run & Output**:

```bash
$ bash rename.sh
$ ls
20250508_report.txt  20250508_notes.txt
```

### Recap

- Automate backups with timestamps
- Monitor system performance live
- Rename files in bulk quickly

Learning Bash scripting is like learning a superpower for your terminal!
