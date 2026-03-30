# Zero Trust Security (ZTS) Architecture

A production-ready implementation of a Zero Trust Security platform, built as part of the MscIT UWS Dissertation project. This application enforces the core principles of NIST SP 800-207 by operating under the assumption that no network is safe and every access request must be continuously authenticated, authorized, and monitored.

## 🚀 Key Features

### 1. Identity & Access Management (IAM)
- **Role-Based Access Control (RBAC):** Strict segregation of duties across distinct departments (SuperAdmin, IT, HR, Finance, CustomerSupport).
- **Stepped-Up Authentication:** Enforces dynamic Multi-Factor Authentication (OTP via email) depending on the assessed risk of the login attempt.
- **Session Management:** Secure, HTTP-only, SameSite strict session cookies with absolute and idle timeouts to prevent hijacking.

### 2. Device & Contextual Trust
- **Device Fingerprinting:** Cryptographic tracking of trusted and untrusted hardware devices. Unrecognized devices trigger high-risk flags and require administrative approval.
- **VPN & Proxy Detection:** Real-time IP resolution to flag impossible travel scenarios and detect anonymizing networks (VPNs/TOR).
- **Time-Based Access Control:** Configurable logical access windows that block off-hours connections.

### 3. Continuous Risk Assessment Engine
Instead of merely checking a password once, every login attempt undergoes a rigorous heuristic examination:
- Historical failure rates for the IP/User.
- Geographic anomalies.
- Device authorization status.
- Velocity checks (preventing brute-force and credential stuffing).

If the aggregate **Risk Score** exceeds configurable thresholds, the access is dynamically degraded, blocked, or challenged.

### 4. Live Telemetry & Security Operations Center (SOC)
- **Prometheus Metrics Endpoint:** Real-time extraction of live security telemetry running via a `/metrics` heartbeat.
- **Grafana Dashboards:** Visualizations tracking failed logins, VPN detection rates, ongoing active sessions, Adaptive MFA triggers, and global risk scores.
- **Audit Logging:** Immutable tracking of every significant interaction in the platform.

## 🛠 Tech Stack

- **Backend:** Node.js, Express.js
- **Database:** Supabase (PostgreSQL)
- **Security:** Helmet, express-rate-limit, custom Anti-CSRF
- **Metrics/Monitoring:** Prometheus, Grafana, PM2
- **Deployment:** Ubuntu Linux VPS, NGINX Reverse Proxy

## 📂 Project Structure

```text
├── middleware/       # Core ZTS checks (auth, continuous risk, CSRF, HMAC)
├── routes/           # API endpoints and page controllers
├── services/         # Business logic (OTP, email, geo-ip, device fingerprinting)
├── public/           # Static assets, CSS layout, client-side JS
├── views/            # Frontend HTML templates
├── server.js         # Application entry point and NGINX proxy mapping
└── schema.sql        # Supabase database architecture and audit triggers
```

## ⚙️ Installation & Deployment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/rajanchand/zerotrustsecurity-demo.git
   cd zerotrustsecurity-demo
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Environment Setup:**
   Create a `.env` file in the root directory:
   ```env
   NODE_ENV=production
   PORT=3000
   SESSION_SECRET=your_super_secret_key
   SUPABASE_URL=your_supabase_url
   SUPABASE_SERVICE_KEY=your_supabase_service_key
   EMAIL_USER=your_smtp_user
   EMAIL_PASS=your_smtp_password
   ```

4. **Run the Server:**
   - For local development: `npm run dev`
   - For production (Process Management): `pm2 start server.js --name zts-live`

## 🔒 Security Posture Note
This project was developed strictly for demonstration and academic evaluation. While it utilizes enterprise-grade paradigms such as cryptographic signing and contextual risk deduction, it serves as a proof-of-concept for the implementation of the Zero Trust Security framework in modern web architectures.
