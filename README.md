# F-14 TOMCAT

Advanced NoSQL Injection Framework

F-14 Tomcat is a modern, modular, and fast tool designed for exploiting NoSQL injection vulnerabilities. While currently focused on MongoDB, it provides advanced techniques to bypass WAFs and extract data efficiently using binary search algorithms.

## Features

- **Advanced Extraction:** Uses Binary Search algorithm for high-speed data extraction (Blind Injection).
- **WAF Evasion:** Supports JA3/TLS Fingerprint impersonation (Chrome/Firefox/Safari) to bypass modern WAFs like Cloudflare.
- **Smart Stability:** Auto-calibration for network jitter and dynamic content filtering to prevent false positives.
- **Auto-Authentication:** Automatically detects session expiration (401/403) and re-authenticates to maintain the session.

- **Multi-Technique:**

    - **Auth Bypass (Technique A)**

    - **Blind Injection (Technique B)**

    - **JS Injection (Technique J)**

- **Flexible Input:** Supports JSON, Form-Data, and GET parameters.

- **Payload Tuning:** Customizable prefix/suffix injection for complex syntax requirements.

## Installation

** 1.Clone the repository**
```bash
git clone [https://github.com/G0odkid/F-14.git](https://github.com/G0odkid/F-14.git)
cd F-14
```

** 2.Install dependencies**
```bash
pip install -r requirements.txt
```

(Note: Ensure you have python 3.x installed.)

## Usage Examples

1. Basic Scan (Auth Bypass Check)
Check if the login page is vulnerable to basic NoSQL injection:
```bash
python3 tomcat.py -u [http://target.com/login](http://target.com/login) -d '{"username": "admin", "password": "123"}' --technique A
```

2. Data Extraction (Blind Injection)
Extract the administrator's password using binary search:
```bash
python3 tomcat.py -u [http://target.com/login](http://target.com/login) -d '{"username": "admin", "password": "*"}' --technique B --param "password"
```

3. WAF Bypass Mode
Impersonate a Chrome browser to bypass WAF protections:
```bash
python3 tomcat.py -r request.txt --impersonate chrome120 --technique B
```

4. High Stability Mode
Set custom timeouts and retries for unstable networks:
```bash
python3 tomcat.py -u [http://target.com/api](http://target.com/api) -d '{"id": 1}' --timeout 15 --retries 5
```

## Roadmap (Upcoming Features)

- Support for other NoSQL databases (Redis, CouchDB, Cassandra).

- Out-of-Band (OOB) extraction via DNS/HTTP.

- HTML/JSON Report generation.

- Header Injection support.


Developer: G0odkid