---
title: "CYBERGAME-2025 {FORENSIC-CHALLENGES}"
subtitle: "⚡ Bastion was a cool challenge read through and feel it⚡"
summary: "* Kenyan version organized by: Ministry of Information,Communications and the Digital Economy*"
date: 2025-06-10
cardimage: cybergame.png
featureimage: cybergame.png
caption: cybergame
authors:
  - Havoc: logo.png
---

## 1. Introduction

Welcome to this comprehensive writeup for the Bastion CTF challenge series! This series of challenges focuses on server security, forensic analysis, and identifying backdoors in a compromised system. Throughout these challenges, we'll explore various aspects of security, from inspecting docker layers to analyzing git repositories for malicious code.

The Bastion series consists of four progressive challenges:
    
1.  **Bastion - So much just from logs**: inspect the logs to find the flag
2. **Bastion - Inspect the file system**: Examining a docker layer for hidden flags
3. **Bastion - Clean bastion**: Accessing a bastion host via SSH and identifying potential issues
4. **Bastion - Feel free to dig in**: Conducting a deeper forensic investigation for attacker traces
5. **Bastion - The backdoor culprit**: Analyzing a git repository to find the source of a backdoor

. Let's dive in and solve them step by step!

### Tools Used
- Linux command line utilities (tar, grep, find, etc.)
- SSH client
- Git
- Base64 encoding/decoding
### **Challenge 1: Bastion - So much just from logs**

![bastion](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup3/images/bastion%20so%20much%20from%20logs.png?raw=true)


**Solution:**

```bash

gzip -d *.gz

cat auth.log* | grep -v -e 'Connection closed by invalid user' -e 'Failed password for invalid user' -e 'Failed none for invalid user' -e 'Invalid user ' -e 'Could not get shadow information' -e 'not allowed because account is locked' -e 'Connection closed by authenticating user' -e 'Failed password for ' | r.csd b64 | r.csd hex

```

This will reveal the flag: `SK-CERT{n3v3r_f0r637_4b0u7_d47_p3r51573nc3}`

  
## 2. Challenge 2: Bastion - Inspect the file system

![bastion](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup3/images/inspect%20the%20file%20system.png?raw=true)


For this challenge, we are provided with a docker layer archive file named `part2_docker_layer.tar.gz`. Our task is to inspect this file system and find any hidden flags.

### Methodology
1. Extract the docker layer archive
2. Inspect the extracted filesystem
3. Search for the flag in the expected format (SK-CERT{})

### Step-by-Step Solution

#### Step 1: Extract the Docker Layer Archive
First, we need to create a directory for our work and extract the archive:

```bash
mkdir -p /home/ubuntu/ctf_challenge
tar -xzf "part2_docker_layer.tar.gz" -C /home/ubuntu/ctf_challenge
```

#### Step 2: Inspect the Extracted Filesystem
Let's list the contents of the extracted directory to get an overview of the filesystem:

```bash
ls -R /home/ubuntu/ctf_challenge
```

This command reveals a complex directory structure with many files and subdirectories. To navigate this efficiently, we need to focus our search.

#### Step 3: Search for the Flag
Since we know the flag format is SK-CERT{}, we can use grep to search for it across all files:

```bash
grep -a -r "SK-CERT{" /home/ubuntu/ctf_challenge/
```

The `-a` flag treats binary files as text, and `-r` performs a recursive search.

This search returns two potential flags:

```
/home/ubuntu/ctf_challenge/19d1ccfb743d216f8186a3e0273a24132bb7c4c8813d741108c14722a85732fe/merged/tmp/persistence:[Fri Apr 18 16:15:22 UTC 2025] i hope they wont find me, and this flag (SK-CERT{n3v3r_f0r637_4b0u7_d47_p3r51573nc3}) keeps on beaconing
/home/ubuntu/ctf_challenge/19d1ccfb743d216f8186a3e0273a24132bb7c4c8813d741108c14722a85732fe/merged/var/data/keylogger.bin:    === LOG START SK-CERT{l34v3_17_70_7h3_pr05} === %s
```

### Key Findings and Flag
We found two potential flags:
1. `SK-CERT{n3v3r_f0r637_4b0u7_d47_p3r51573nc3}` in `/tmp/persistence`
2. `SK-CERT{l34v3_17_70_7h3_pr05}` in `/var/data/keylogger.bin`

After verification, the correct flag is: **SK-CERT{l34v3_17_70_7h3_pr05}** the other one was the flag for the very first challenge not included in this series because it was easy to get.

### Lessons Learned
- Always check binary files when searching for flags
- Multiple potential flags might be present; verification is important
- The location of a flag can provide context (in this case, a keylogger binary)

## 3. Challenge 3: Bastion - Clean bastion

![bastion](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup3/images/clean%20bastion.png?raw=true)

> ssh://exp.cybergame.sk:7009 (ratchet:23ekmnjr4bh5tgvfhbejncidj)

For this challenge, we need to SSH into the provided bastion host and investigate the system.

### Methodology
1. Establish an SSH connection to the bastion host
2. Investigate the system for any issues or flags
3. Document findings

### Step-by-Step Solution

#### Step 1: Connect to the Bastion Host
First, we need to connect to the provided SSH server:

```bash
ssh -p 7009 ratchet@exp.cybergame.sk
```

When prompted, enter the password: `23ekmnjr4bh5tgvfhbejncidj`

Upon successful connection, we're greeted with a welcome message that contains our flag:

```
Welcome, Ratchet!
Come in and don't be shy
     SK-CERT{bru73_f0rc1n6_u53r5_w0rk5}
```

#### Step 2: Verify System Status
Even though we've found the flag, let's perform a basic system check to ensure everything is as expected:

```bash
ls -la /home/ratchet
ls -la /tmp
ls -la /var/tmp
```

These commands show no suspicious files in the home directory or temporary directories.

### Key Findings and Flag
The flag was displayed in the welcome message upon SSH login: **SK-CERT{bru73_f0rc1n6_u53r5_w0rk5}**

### Lessons Learned
- Sometimes flags are hidden in plain sight, like welcome messages
- Initial reconnaissance is crucial, even when a flag is immediately visible
- The flag suggests this challenge was about brute forcing user credentials

## 4. Challenge 4: Bastion - Feel free to dig in

![bastion](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup3/images/feel%20free%20to%20dig%20in.png?raw=true)

> ssh://exp.cybergame.sk:7009

For this challenge, we need to conduct a deeper forensic investigation of the same bastion host to find traces of attackers.

### Methodology
1. Connect to the bastion host
2. Conduct a thorough forensic investigation
3. Look for unusual files, configurations, or hidden data
4. Document all findings

### Step-by-Step Solution

#### Step 1: Connect to the Bastion Host
We use the same SSH connection as in the previous challenge:

```bash
ssh -p 7009 ratchet@exp.cybergame.sk
```

Password: `23ekmnjr4bh5tgvfhbejncidj`

#### Step 2: Investigate User Accounts and Home Directories
Let's check the user accounts and home directories:

```bash
cat /etc/passwd
ls -la /home
```

We notice there's an `admin` user in addition to our `ratchet` user.

#### Step 3: Check SSH Configuration and Keys
Since we're dealing with a bastion host, SSH configuration is a good place to look:

```bash
ls -la /home/ratchet/.ssh
cat /home/ratchet/.ssh/authorized_keys
```

In the authorized_keys file, we find a suspicious entry:

```
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOSeOZtJmXS7zliVg5tEaEk9KvhIRn4S3FBjLuo1s0eUvHi6HkzuLTNXiphR8Lth/DWQNeC/A+meex8Y09RtZQA= hacker-U0stQ0VSVHtoMEx5X00wTGx5X1RIM3lfNHIzXzV0aUxsX2gzUjN9
```

The comment on this key looks like it contains base64-encoded data.

#### Step 4: Decode the Base64 String
Let's decode the base64 string in the comment:

```bash
echo "U0stQ0VSVHtoMEx5X00wTGx5X1RIM3lfNHIzXzV0aUxsX2gzUjN9" | base64 -d
```

This reveals our flag: `SK-CERT{h0Ly_m0Lly_TH3y_4r3_5tiLl_h3R3}`

### Key Findings and Flag
We found a suspicious SSH key in the authorized_keys file with a base64-encoded comment that contained the flag: **SK-CERT{h0Ly_m0Lly_TH3y_4r3_5tiLl_h3R3}**

### Lessons Learned
- Attackers often leave backdoors for persistent access
- SSH authorized_keys files are common places for backdoors
- Base64 encoding is frequently used to hide information
- Always check for unusual comments or strings that might contain encoded data

## 5. Challenge 5: Bastion - The backdoor culprit

![bastion](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup3/images/the%20backdoor%20culprit.png?raw=true)

For this challenge, we are provided with a git repository archive (`part5_ssh-bastion-repo.tar.gz`) and need to identify who added the backdoor we found in the previous challenge.

### Methodology
1. Extract the git repository
2. Explore the repository structure
3. Analyze the commit history
4. Identify when and by whom the backdoor was introduced

### Step-by-Step Solution

#### Step 1: Extract the Git Repository
First, let's extract the provided archive:

```bash
mkdir -p /home/ubuntu/bastion_repo_ctf
tar -xzf "part5_ssh-bastion-repo.tar.gz" -C /home/ubuntu/bastion_repo_ctf
```

#### Step 2: Explore the Repository Structure
Let's see what files are in the repository:

```bash
ls -R /home/ubuntu/bastion_repo_ctf/ssh-bastion-repo
```

Output:
```
/home/ubuntu/bastion_repo_ctf/ssh-bastion-repo:
Dockerfile  docker-compose.yml  issue.generic  motd
README.md   issue.admin         issue.ratchet  sshd_config
```

#### Step 3: Examine the Dockerfile
Since we know the backdoor was in the SSH authorized_keys file, let's check the Dockerfile:

```bash
cat /home/ubuntu/bastion_repo_ctf/ssh-bastion-repo/Dockerfile
```

In the Dockerfile, we find the suspicious SSH key being added:

```dockerfile
RUN mkdir -p /home/ratchet/.ssh && \
    echo -e "\
ecdsa-sha2-nistp256 AAAAvZHODysGbxHo1wGtqbqi1Ffnr2li7j8ov/V26Nt4w/HR26mWOtT/APG1qBilJoVmCQChz/hCWuIWwzqqZNe1BQ== ratchet@infocube\n\
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOSeOZtJmXS7zliVg5tEaEk9KvhIRn4S3FBjLuo1s0eUvHi6HkzuLTNXiphR8Lth/DWQNeC/A+meex8Y09RtZQA= hacker-U0stQ0VSVHtoMEx5X00wTGx5X1RIM3lfNHIzXzV0aUxsX2gzUjN9\
" > /home/ratchet/.ssh/authorized_keys
```

#### Step 4: Analyze the Git History
Now, let's check the commit history for the Dockerfile to see who added this backdoor:

```bash
cd /home/ubuntu/bastion_repo_ctf/ssh-bastion-repo
git log --all --pretty=oneline --abbrev-commit Dockerfile
```

Output:
```
434e557 merge suggested changes from colleague
a222654 update ssh keys SK-CERT{r09U3_3MPL0Y33_0r_5uPpLycH41n}
fe00ee7 upgrade base image
018ab72 harden user passwords
3f9744d bastion deployment. initial commit
```

The commit message for `a222654` looks suspicious and contains what appears to be our flag.

#### Step 5: Examine the Specific Commit
Let's look at the details of this commit:

```bash
git show a222654
```

Output:
```
commit a22265452b4b9e02dd3492165c953dd53d1ba393
Author: Ratcher Tailhorn <employee@infocude>
Date:   Fri Apr 18 23:30:01 2025 +0200
    update ssh keys SK-CERT{r09U3_3MPL0Y33_0r_5uPpLycH41n}
diff --git a/Dockerfile b/Dockerfile
index 8fc2b95..41b13b5 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -21,7 +21,8 @@ COPY sshd_config /etc/ssh/sshd_config
 
 RUN mkdir -p /home/ratchet/.ssh && \
     echo -e "\
-ecdsa-sha2-nistp256 AAAAvZHODysGbxHo1wGtqbqi1Ffnr2li7j8ov/V26Nt4w/HR26mWOtT/APG1qBilJoVmCQChz/hCWuIWwzqqZNe1BQ== ratchet@infocube\n
+ecdsa-sha2-nistp256 AAAAvZHODysGbxHo1wGtqbqi1Ffnr2li7j8ov/V26Nt4w/HR26mWOtT/APG1qBilJoVmCQChz/hCWuIWwzqqZNe1BQ== ratchet@infocube\n\
+ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOSeOZtJmXS7zliVg5tEaEk9KvhIRn4S3FBjLuo1s0eUvHi6HkzuLTNXiphR8Lth/DWQNeC/A+meex8Y09RtZQA= hacker-U0stQ0VSVHtoMEx5X00wTGx5X1RIM3lfNHIzXzV0aUxsX2gzUjN9\
 " > /home/ratchet/.ssh/authorized_keys
```

This confirms that the backdoor was added by "Ratcher Tailhorn" in a commit with the message containing our flag.

### Key Findings and Flag
The backdoor was introduced by a user named "Ratcher Tailhorn" in commit `a222654`. The commit message itself contains the flag: **SK-CERT{r09U3_3MPL0Y33_0r_5uPpLycH41n}**

### Lessons Learned
- Git history is a valuable forensic resource
- Commit messages and author information can reveal the source of malicious code
- Backdoors are often introduced in seemingly innocent updates
- Always review code changes, especially those affecting security configurations

## 6. Conclusion

These challenges demonstrate the importance of thorough system inspection, understanding common backdoor techniques, and the value of version control history in forensic investigations.

### Final Thoughts
The Bastion series provides an excellent progression of challenges that build upon each other, telling a coherent story of system compromise and investigation. The skills practiced here are directly applicable to real-world security scenarios, making this an educational and practical CTF series.

## 7. References

### Useful Commands
- `tar -xzf <archive.tar.gz> -C <destination>` - Extract a tar.gz archive
- `grep -a -r "pattern" <directory>` - Recursively search for a pattern
- `ssh -p <port> <user>@<host>` - Connect to an SSH server
- `echo "<string>" | base64 -d` - Decode a base64 string
- `git log --all --pretty=oneline --abbrev-commit <file>` - View git history for a file
- `git show <commit>` - Show details of a specific commit

### Additional Resources
- [Docker Documentation](https://docs.docker.com/)
- [SSH Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [Git for Security Professionals](https://git-scm.com/book/en/v2)
- [Linux Forensics Tools](https://www.kali.org/tools/)


The next challenge on forensics

# [★★☆] Eugene’s FATigue

[](https://github.com/lukaskuzmiak/cybergame.sk-2025-writeups/tree/main/Eugene's%20FATigue#-eugenes-fatigue)

## FATigue
![eugene](https://miro.medium.com/v2/resize:fit:640/format:webp/1*2YNYZYcfvDyAXyLPS9WEGw.png)

*Solution*

The head of the challenge gave us a hint it was a *FATdisk image*.so after mounting the disk then  we got a file named *secret.txt* and innit we got the below text.

```
This feels like FX-PREG{cy41a_5vTu7} to me. Cannot hide my best work here.
```

The text  `FX-PREG{cy41a_5vTu7}` is the flag but in ROT13 so we decode it to get the flag

```shell
SK-CERT{pl41n_5iGh7}
```
## **Is that it?**
![eugene](https://miro.medium.com/v2/resize:fit:720/format:webp/1*FDc02Ija-sH1SwY_5w-TUA.png)


*Solution*

Just casually searching for stuff in a hex editor, I noticed a PDF in there somewhere; there is some weird base64 inside the PDF:

```
VuwtuTeEEf9uthkAwc1_zzpRq9x4c/LV0TOw5x6a_U0stQ0VSVHs3aDFzX1dBU18xN19hZnRlcl9hbGx9$EucR/FqMoVaZvjx3OvGT_EV4u/Y7EDwDeA/w9QO3+^ALYXhvTD3R1JcGJUgKFi_mhzkezdqaIHzm261y9IQ_EV4u/Y7EDwDeA/w9QO3+
```

Inside it is a flag: 
```shell
U0stQ0VSVHs3aDFzX1dBU18xN19hZnRlcl9hbGx9$EucR
```

after decoding we get a cool flag...   `SK-CERT{7h1s_WAS_17_after_all}`


## **Was that the only file?**

![eugene](https://miro.medium.com/v2/resize:fit:720/format:webp/1*2g_-N1aMCuWe3x4oKQeh1A.png)

*Solution*

Ok, enough messing around with `strings` and ***hex editors***, we were clearly intended to actually recover data for real.

Here the recovery was attempted with **PhotoRec/TestDisk**, in one of the runs corrupted files were enabled; this recovered the files in [`recovered/`](https://github.com/lukaskuzmiak/cybergame.sk-2025-writeups/blob/main/Eugene's%20FATigue/Solution/recovered). The corrupted ZIP can be unpacked with:

```shell
7z x b0003185_file.zip
```

This unpacks three files:

```
fifth.txt
file
fourth-flag.aes.b64.txt
```

`file` is the file relevant for the third flag and it contains the following text:

> Begin by gently whispering to a fresh beetroot, ensuring it's thoroughly startled before peeling. Simmer beef slices under moonlight until they hum softly, indicating readiness. Combine with precisely three beetroot dreams, diced finely, and a pinch of yesterday’s laughter. Allow the mixture to philosophize in an oven preheated to curiosity. Occasionally stir with a skeptical spoon, preferably wooden, until the aroma resembles purple jazz. Serve only after garnishing with a sprinkle of questions unanswered, paired with a side dish of a sautéed third flag SK-CERT{R3c0V3r3D_R3cip3}.

The flag was cool and was:

```
SK-CERT{R3c0V3r3D_R3cip3}
```

## It tastes like a poem
![keep](https://miro.medium.com/v2/resize:fit:720/format:webp/1*GcYsODwaCtsSHUV2IpdTJA.png)

*Solution*

It seems the `fourth-flag.aes.b64.txt` is the file for this challenge.

I wrote `aes_decrypt.py` 
```python
import base64
from Crypto.Cipher import AES

# Load and decode the file
with open("fourth-flag.aes.b64.txt", "r") as f:
    data = base64.b64decode(f.read().strip())

# Best working parameters from our tests
null_key = bytes(32)  # 32 null bytes for AES-256
iv = data[:16]        # First 16 bytes as IV
ciphertext = data[16:]

# Decrypt using AES-CBC
cipher = AES.new(null_key, AES.MODE_CBC, iv=iv)
decrypted = cipher.decrypt(ciphertext)

# Clean up padding and save full output
try:
    # Remove PKCS#7 padding if present
    pad_len = decrypted[-1]
    if pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
        decrypted = decrypted[:-pad_len]
    
    # Save to file and print first 200 characters
    with open("decrypted_poem.txt", "wb") as f:
        f.write(decrypted)
    
    print("Full decryption saved to decrypted_poem.txt")
    print("\nFirst 200 characters:")
    print(decrypted[:200].decode('utf-8', errors='replace'))

except Exception as e:
    print("Error cleaning padding:", e)
    print("Raw output (first 200 bytes):")
    print(decrypted[:200])
```

and it got the flag right away 
The Results are as below *cool and juicy!!!!!*
![eugene]

```
SK-CERT{d0esnt_m4ke_s3nse_7o_d0_f0rensics_anym0r3}
```

## **Wrapping it up**

![eugene](https://miro.medium.com/v2/resize:fit:720/format:webp/1*hcpfwA7nCsHWze2Dz2HVGQ.png)

**Solution**

The `fifth.txt` contains the below text with the flag
![eugene]

`SK-CERT{1mp0ss1bly_H4RD}` 

That was the flag for this challenge. It seems **PhotoRec/TestDisk** recovered enough mess after the ZIP or 7z did a good job to extract this anyway, not sure, to be honest.

>*thats it on the eugene fatigue now to the next challenge:*
# [★☆☆] The Chronicles of Greg 2 — Frustrating compression

On this challenge it was cold to me but a nigga gave me glasses to see it through though it was the last minute and the servers were down i coulnt submit the results but were correct after crawling though other writeups and in deed i was correct.that made me cool.enough with the crap  lets dive in :

### 1. **The Chronicles of Greg Frustrating compression**


There was a **lot** of archives here, after fiddling with it manually for a minute or so, it quickly became clear that it was a no-go. I asked chat-gpt to help create a code several times and at long last i got it right with few tweaks it was ready to go....

`extract.py`

```python
#!/usr/bin/env python3
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile

import py7zr
import rarfile

START_ARCHIVE = '00114021.tar'
OUTPUT_DIR = '/tmp/out'

# Supported archive extensions
ARCHIVE_EXTENSIONS = ('.zip', '.tar', '.rar', '.7z')

os.makedirs(OUTPUT_DIR, exist_ok=True)


def is_archive(filename):
    return filename.lower().endswith(ARCHIVE_EXTENSIONS)


def extract_archive(filepath, extract_to):
    if filepath.endswith('.zip'):
        with zipfile.ZipFile(filepath, 'r') as zf:
            zf.extractall(extract_to)
    elif filepath.endswith('.tar'):
        with tarfile.open(filepath, 'r:*') as tf:
            tf.extractall(extract_to, filter='tar')
    elif filepath.endswith('.rar'):
        with rarfile.RarFile(filepath) as rf:
            rf.extractall(extract_to)
    elif filepath.endswith('.7z'):
        with py7zr.SevenZipFile(filepath, mode='r') as z:
            z.extractall(extract_to)
    else:
        raise ValueError(f'Unsupported archive: {filepath}')


processed_archives = set()


def process_archive(filepath):
    abs_path = os.path.abspath(filepath)
    if abs_path in processed_archives:
        logging.warning('Skipping already processed archive: %s', filepath)
    else:
        logging.debug('Extracting archive: %s', filepath)
    processed_archives.add(abs_path)

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            extract_archive(filepath, tmpdir)
        except Exception:
            logging.exception(f'Failed to extract {filepath}')
            return

        for root, _, files in os.walk(tmpdir):
            for name in files:
                full_path = os.path.join(root, name)
                logging.debug('Found file: %s', full_path)
                if is_archive(name):
                    logging.debug('Recursing into nested archive: %s', full_path)
                    process_archive(full_path)
                    print('.', end='', flush=True)
                else:
                    rel_path = os.path.relpath(full_path, tmpdir)
                    out_path = os.path.join(OUTPUT_DIR, rel_path)
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    logging.debug('Copying non-archive file to output: %s', out_path)
                    shutil.copy2(full_path, out_path)
                    print('+', end='', flush=True)


if __name__ == '__main__':
    process_archive(START_ARCHIVE)
    print()
```

just run the code and let magic and power do its work ....to unpack it all, then just found the flag:...
![greg]



>the next part was the most challenging part even with the glasses it was hard headed to me.i coundnt crack it but i will try to,,

---

> hope you enjoyed the reading.Feel free to tag me.