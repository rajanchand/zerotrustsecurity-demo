# Simple explanation of this project (human-friendly)

This file explains the project's code in plain English. It tells you what each file does, how the pieces fit together, and how to run the app locally.

---

High-level summary
- This is a small demonstration web app for a "Zero Trust" login flow (MSc dissertation work).
- It's a Node.js + Express app that uses Supabase (Postgres-compatible) as the database.
- Key features: username/password login, device registration & approval, OTP (one-time password), simple risk scoring, audit logs, and small admin pages for managing users/devices/IP rules.

What the main files do (plain language)
- `server.js` — Program entry point. Starts Express, sets up sessions, adds two middleware checks (login required and risk flag), and mounts the route modules. If you open the app, it listens on port 3000 by default.

- `package.json` — Lists dependencies and a few npm scripts. Use `npm start` to run the app.

- `db.js` — Initializes the Supabase client. All database calls in the app go through this client. It reads credentials from your `.env` file. If credentials are missing, it exits with an error.

- `setup-db.js` — Helper that prints SQL to create the tables this app expects (users, devices, sessions, otp_store, risk_logs, audit_log, ip_rules, departments). It's intended to be pasted in the Supabase SQL editor.

- `seed.js` — Adds a small set of example users (superadmin, hruser, etc.) with bcrypt-hashed passwords. Run once after you create tables.

Middleware (runs on many requests)
- `middleware/auth.js` — Checks if the request is for login/static files; otherwise, enforces that the user has a session, session timeout (15 minutes), and that they have passed OTP verification. If not, redirects to `/login` or `/otp` as needed.

- `middleware/rbac.js` — Simple role-based access control. You give it a list of allowed roles and it checks the user's session role. SuperAdmin always passes.

- `middleware/riskCheck.js` — Small helper that sets `req.session.highRisk = true` if the session's riskScore is above 60. This is used for UI or later logic.

Route files (what they do in simple terms)
- `routes/authRoutes.js` — Handles login, OTP verify, logout, and a `/api/session` endpoint. Login flow: check username/password, register the device (fingerprint), decide if device needs approval, compute a risk score, generate an OTP, store session state, and return success that points the client to `/otp`.

- `routes/dashboardRoutes.js` — Serves the dashboard and provides the `/api/dashboard-data`, `/api/activity`, and `/api/risk-data` endpoints that the frontend pages call to show info.

- `routes/mappingRoutes.js` — Admin pages for user management, departments, and device approval. Includes APIs to create/delete users, change roles, approve/reject devices, and work with departments.

- `routes/networkRoutes.js` — IP rules management and a device-health overview for admins.

Services (small helper modules)
- `services/auditService.js` — Writes security events to an `audit_log` table and reads logs back.

- `services/deviceService.js` — Finds, registers, approves, rejects devices. A device has a fingerprint, browser/os, IP, country, and an `approved` flag. New devices are added as `approved: false`.

- `services/geoService.js` — A tiny simulated geolocation module. For demo purposes it maps some IPs to countries and flags simple VPN ranges.

- `services/otpService.js` — Creates 6-digit OTP codes, stores them in `otp_store`, and verifies them. OTPs expire after 5 minutes. In this demo it prints the code to console (so you can see it).

- `services/riskEngine.js` — Calculates a simple risk score based on factors (new device, new country, failed logins, VPN, admin unknown IP). It writes a `risk_logs` entry and returns a score and level (Low/Medium/High).

- `services/auditService.js` — (already above) helper to log events and fetch logs.

Views (frontend pages)
- `views/*.html` — Simple HTML pages for login, OTP, dashboard, mapping (admin), network, register-device, risk, and a small `views/simple-form.html` (a tiny local demo form added earlier). These pages use a small client script (`public/js/app.js`) to talk to the server APIs.

How the login flow works (step-by-step, simple)
1. User submits username + password from `/login`.
2. Server checks the password. If wrong, it increases `failed_attempts` and returns an error.
3. If correct, server reads the device fingerprint and registers the device (or updates last_seen).
4. If the device is new and the user is not auto-approved (only SuperAdmin is auto-approved), the login is blocked until an admin approves the device.
5. Server calculates a risk score (few simple rules) and stores the score in the session.
6. Server generates a 6-digit OTP, logs the event, and stores user info in the session but marks `otpVerified = false`.
7. The client is redirected to `/otp`. User enters the code; server verifies it and finally sets `otpVerified = true` in the session.
8. User can now access protected pages like `/dashboard`.

How to run this project locally (quick)
1. Create a Supabase project and get `SUPABASE_URL` and `SUPABASE_KEY` (or use any Postgres-like service and adapt the code).
2. Create a `.env` file at the project root with at least:

   SUPABASE_URL=your-supabase-url
   SUPABASE_KEY=your-supabase-key
   SESSION_SECRET=choose-a-secret

3. Run the SQL from `setup-db.js` in the Supabase SQL editor to create tables.
4. Run `npm install` to install dependencies.
5. Run `npm run seed` to create demo users (after you created tables).
6. Run `npm start` and open http://localhost:3000 in your browser.

Notes: demo conveniences and safety
- OTP codes are printed to the server console for demo. In production you'd send them to email/SMS.
- The `geoService` is a stub; replace it with a real IP-to-country lookup if you need accurate data.
- Session cookie `secure` is set to false for local dev; set it to true when using HTTPS in production.

Simple contract / inputs & outputs (2-4 bullets)
- Inputs: username/password (login), device fingerprint (from client), OTP code, admin actions via APIs (JSON).
- Outputs: JSON responses for API endpoints (success/failure, redirect URL, risk info) and HTML pages for UI.
- Error modes: database errors return server error messages; invalid credentials or OTPs return user-friendly JSON messages.

Common edge cases (and how the code handles them)
- Wrong password: increments `failed_attempts`; after 5 attempts account is locked/blocked.
- New device: blocks login until admin approval (unless SuperAdmin).
- Expired OTP: server returns 'OTP has expired' and user must request a new login.
- Missing Supabase credentials: `db.js` exits with an error telling you to add env variables.

Small next steps I can do for you (pick any)
- Wire `views/simple-form.html` into the app as `/simple-form` route and serve it.
- Add server-side endpoint that receives the simple form submission and saves it to the database or sends an email.
- Convert the `geoService` to use a real geolocation API.
- Add a short developer script to run the app with `nodemon` for development.

If you'd like, I can also create a simplified version of one of the core files (for example `server.js`) with brief inline comments that read like a human explanation. Tell me which file you'd like simplified first.

---

Completion note
- I read the main server, routes, middleware, services, and views and wrote this plain-language README to describe what the project does and how to run it. If you want me to modify files to include inline human-readable comments, I can do that next.
