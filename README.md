# Zero Trust Security (ZTS) Architecture Demo
**A practical approach to securing remote work environments.**

Hi there! Welcome to the practical demonstration of a Zero Trust Security (ZTS) model, built entirely from the ground up as part of my MSc IT Dissertation. 

Traditionally, companies relied on simple passwords and secure company WiFi to keep hackers out. But in today’s remote work era, where employees log in from coffee shops and home networks all over the world, that approach no longer works. This project implements the **NIST SP 800-207** standard of "Continuous Verification", meaning the system never blindly trusts anyone—even after they log in.

---

## 🚀 What Does This System Actually Do?

I've built a comprehensive security suite that acts like an intelligent, automated security guard. Here are all the core features powering the platform:

### 🧠 The Adaptive Risk Engine
Every time someone tries to log in, the system calculates a dynamic "Trust Score" in the background before deciding whether to let them in:
*   **Geo-Fencing:** Enforces country-specific location rules based on what HR department the user belongs to.
*   **Impossible Travel Detection:** It uses physics to catch anomalies. If an employee logs in from Nepal, and 5 minutes later there is a login attempt from London, the system flags it as physically impossible and blocks access.
*   **Device Fingerprinting:** When an employee buys a new laptop or uses an unrecognized phone, the system quarantines the session until an Admin manually approves the new hardware.
*   **Strict Working Hours:** If someone tries to access sensitive data outside of their department's authorized shift hours, the system immediately recognizes the "Off-Hours" anomaly and raises their risk score.

### 🌐 Network Trust & Remote Work Policies
Not all internet connections are safe, so the platform categorizes them automatically:
*   **Network Classification:** The system actively identifies whether a connection is coming from a secure Corporate IP, an untrusted Public Wi-Fi, or if the user is hiding behind a commercial VPN.
*   **Trusted Home Offices:** Employees can formally request to register their personal home network. Once approved by an Admin, the system recognizes their "Home Office" as a safe zone.

### 📱 Passwordless OTP & Step-Up Auth
*   **Dynamic Authentication:** Instead of using weak static passwords, users authenticate via secure One-Time Passwords (OTPs) sent directly to their email. 
*   **Step-Up Auth:** If an employee's risk score suddenly spikes while they are already logged in, the system will forcefully freeze their session and demand re-authentication.

### 🛡️ Real-Time Monitoring & Incident Response
*   **Centralized SOC Dashboard:** An incredibly clean, minimalist Command Center designed for executives and IT admins. It tracks system health, maps global login activity in real-time, and allows admins to permanently ban malicious users with one click.
*   **Instant Slack Alerts:** Security teams don't need to stare at logs all day. If a high-risk event occurs (like a VPN login or an impossible travel scenario), the platform pushes a formatted alert straight to a private Slack channel.
*   **Deep Forensic Logs:** Every single action is tracked, logged, and connected to an internal Prometheus metrics engine for advanced data analysis.

---

## 🛠️ How to Install & Run the Code

I've made sure this project is incredibly easy to boot up, whether you want to test it locally on your laptop or deploy it to a live production server.

### Option 1: Running it Locally (For Testing)
If you just want to run it on your own computer:

1. **Download the code:**
   ```bash
   git clone https://github.com/rajanchand/zerotrustsecurity-demo.git
   cd zerotrustsecurity-demo
   ```
2. **Install the required packages:**
   ```bash
   npm install
   ```
3. **Set up the Environment File:**
   Create a file named `.env` in the main folder. You will need to paste in your Supabase connection keys, your Resend Email API key, and your Slack Webhook URL.
   *(Tip: Add `RESEND_TO_OVERRIDE=your_email@gmail.com` to the `.env` file so all OTPs go directly to you while testing!)*
4. **Boot it up:**
   ```bash
   node server.js
   ```
   Open your browser and navigate to **http://localhost:3000**.

### Option 2: Deploying to a Live VPS (Ubuntu/Linux)
If you want to put it on the public internet, I wrote an automated script to handle the heavy lifting.

1. **Log into your server via SSH:**
   ```bash
   ssh root@your_server_ip_address
   ```
2. **Download the code to the root directory:**
   ```bash
   git clone https://github.com/rajanchand/zerotrustsecurity-demo.git /root/zts-web
   cd /root/zts-web
   ```
3. **Configure your API keys:**
   Use a text editor (like `nano .env`) to securely add your API keys just like in the local setup.
4. **Launch the deployment script:**
   ```bash
   bash deploy.sh
   ```
   *Sit back and relax! This script will automatically install Node.js, configure Nginx as a secure reverse proxy, request a free SSL Certificate from Let's Encrypt so you get the padlock icon, and launch the platform permanently in the background.*

---
**Tech Stack:** JavaScript, Node.js, Express, Supabase (PostgreSQL),
