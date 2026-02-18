# 🛡️ Anirod — Android Security Scanner

A web-based Android APK security scanner that detects vulnerabilities, dangerous permissions, hardcoded secrets and insecure code.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Flask-Dashboard-green)
![Security](https://img.shields.io/badge/Security-Android-red)

## 🔍 What It Detects
- Dangerous permissions (Camera, SMS, Location, Storage)
- Deadly permission combos (Storage + Internet = file theft)
- Hardcoded secrets (API keys, passwords, AWS keys, JWT tokens)
- Insecure code (SSL bypass, weak encryption, SQL injection)

## 🚀 Features
- Dark themed web dashboard
- Drag and drop APK upload
- Risk scoring 0-100
- PDF report generation
- Scan history (SQLite)
- Demo mode

## ⚡ Quick Start
```bash
git clone https://github.com/Kali-ai007/Anirod.git
cd Anirod
pip install flask reportlab
python3 app.py
```
Open: http://localhost:5000

## ⚠️ Disclaimer
For educational and security research purposes only.
Only scan APKs you own or have permission to test.

## 👨‍💻 Author
Kushal — cybersecurity enthusiast and developer.
Also check out: [SecureFlow](https://github.com/Kali-ai007/SecureFlow) | [Hydra](https://github.com/Kali-ai007/Hydra)
