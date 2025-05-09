# Vulnerable Web Application

A deliberately vulnerable web application designed for **educational purposes**, specifically tailored for beginners to practice web application security testing. This project was created as part of a student thesis in IT security and penetration testing.

## Implemented Vulnerabilities

The application currently includes the following vulnerabilities:

- SQL Injection (SQLi)
- Authentication Bypass
- Command Injection (CMDi)
- Local File Inclusion (LFI)
- Business Logic Flaws

Each vulnerability includes a CTF-style flag for capture.

> **Note**: Brute forcing exercises use the PortSwigger username and password lists:
> - https://portswigger.net/web-security/authentication/auth-lab-usernames
> - https://portswigger.net/web-security/authentication/auth-lab-passwords

## ⚠️ Disclaimer

This application is intended **solely for educational use** in controlled environments. Vulnerabilities may not reflect real-world complexity, and bugs may exist due to its nature as a student project.

---

## 🚀 Setup Instructions

### Option 1: Docker Setup (Recommended)

```bash
git clone https://github.com/Adam-Tew/Vulnerable-Web-Application.git
cd vwa
docker compose up -d
```

### Option 2: Manual Setup

#### Initialize Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Install Dependencies

```bash
pip install -r requirements.txt
```

#### Run the Application

```bash
python3 main.py
```

---

## 🐛 Known Issues

When working with the "Authentication Bypass via Encryption Oracle" vulnerability, you may experience:

1. **Cookie Persistence** – Old session cookies may affect exploit behavior.
2. **Redirect Loop** – Possible infinite redirect to dashboard post-exploit.
3. **Flag Reset** – Flags may reset due to the way session handling is implemented.

> If you encounter these or similar issues, use the **"Reset Lab"** button on the page footer.

---

## 📅 Planned Features

- Step-by-step documentation for each vulnerability
- Enhanced hint system highlighting vulnerable parameters
- Isolated cookie storage to prevent flag reset issues
- Unique CTF challenges and extended scenarios

### Upcoming Vulnerabilities

- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Unrestricted File Upload (UFU)
- Server-Side Template Injection (SSTI)
- Broken Access Control & IDOR
- Common API vulnerabilities

---

Enjoy learning and hacking ethically! 🛡️
