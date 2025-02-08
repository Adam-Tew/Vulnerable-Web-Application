# Vulnerable Web Application

A deliberately vulnerable web application designed for educational purposes, specifically for beginners to practice web application security testing skills. This project was created by an IT penetration testing student.
## Currently Implemented Vulnerabilities
```
* SQL Injection (SQLi)
* Authentication Bypass
* Command Injection (CMDi)
* Local File Inclusion (LFI)
* Business Logic Flaws
```
Each vulnerability has an associated CTF-style flag to capture.
Disclaimer: This application was created for educational purposes only. As a student project, some vulnerabilities may not perfectly mirror real-world scenarios, and there might be unintended bugs.

## Setup Instructions
### Initialize Virtual Environment
```
python3 -m venv venv
source venv/bin/activate
```
### Install Dependencies
```
pip install pycryptodome
pip install flask
pip install base58
```
### Run the Application
```
python3 run.py
```

## Known Issues
When working with the "Authentication Bypass via Encryption Oracle" vulnerability, you may encounter the following issues:
```
1. Cookie persistence: Previous user cookies may remain active, causing their username to be used and decrypted instead of yours
2. Dashboard redirect loop: After successful exploitation, you might get stuck in a continuous redirect to the dashboard
3. Flag reset: Due to the current implementation, exploiting this vulnerability will reset any previously captured flags
```
To resolve these or any other issues, use the "Reset Lab" button at the bottom of the webpage.

## Planned Features:
```
* Detailed documentation for solving each vulnerability
* Enhanced hint system highlighting vulnerable parameters and locations
* Separate cookie storage for flags to prevent resets
* Special flag challenges

* Additional vulnerabilities:
	* Cross-Site Scripting (XSS)
	* Cross-Site Request Forgery (CSRF)
	* Upload File Unrestricted (UFU)
	* Server-Side Template Injection (SSTI)
	* Broken Access Control & Insecure Direct Object References (BAC & IDOR)
	* API vulnerabilities
```
