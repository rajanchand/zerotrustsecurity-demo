#!/bin/bash
# deploy.sh - Deploy ZTS from GitHub to VPS
# Run this on the VPS: bash /root/deploy.sh

set -e  # Exit immediately if any command fails

REPO_URL="https://github.com/rajanchand/Uws-zts-demo.git"
APP_DIR="/root/zts-app"
APP_NAME="zts"
VPS_IP=$(curl -s ifconfig.me)

echo ""
echo "================================================"
echo "   ZTS - Zero Trust Security Deployment"
echo "================================================"
echo "  Repo : $REPO_URL"
echo "  Dir  : $APP_DIR"
echo "  IP   : $VPS_IP"
echo ""

# ─── Step 1: Install Node.js 20 (if not installed) ─────────────────────────
if ! command -v node &> /dev/null; then
  echo "[1/7] Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
else
  echo "[1/7] Node.js already installed: $(node -v)"
fi

# ─── Step 2: Install PM2 (if not installed) ─────────────────────────────────
if ! command -v pm2 &> /dev/null; then
  echo "[2/7] Installing PM2..."
  npm install -g pm2
else
  echo "[2/7] PM2 already installed"
fi

# ─── Step 3: Clone or Pull from GitHub ──────────────────────────────────────
echo "[3/7] Getting latest code from GitHub..."
if [ -d "$APP_DIR/.git" ]; then
  echo "  → Repo exists, pulling latest..."
  cd "$APP_DIR"
  git pull origin main
else
  echo "  → Cloning fresh..."
  rm -rf "$APP_DIR"
  git clone "$REPO_URL" "$APP_DIR"
  cd "$APP_DIR"
fi

# Get the current commit hash for logging
GIT_COMMIT=$(git rev-parse --short HEAD)
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "  → Deployed commit: $GIT_COMMIT on branch: $GIT_BRANCH"

# ─── Step 4: Install dependencies ───────────────────────────────────────────
echo "[4/7] Installing npm dependencies..."
npm install --omit=dev

# ─── Step 5: Setup .env (IMPORTANT: create this manually first time) ─────────
echo "[5/7] Checking .env file..."
if [ ! -f "$APP_DIR/.env" ]; then
  echo ""
  echo "  ⚠️  WARNING: No .env file found!"
  echo "  Please upload your .env file:"
  echo "  scp .env root@$VPS_IP:$APP_DIR/.env"
  echo ""
  echo "  Then re-run this script."
  exit 1
else
  echo "  → .env file found ✓"
fi

# ─── Step 6: Configure Nginx ─────────────────────────────────────────────────
echo "[6/7] Configuring Nginx..."
cat > /etc/nginx/sites-available/zts << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF

ln -sf /etc/nginx/sites-available/zts /etc/nginx/sites-enabled/zts
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
echo "  → Nginx configured ✓"

# ─── Step 7: Start/Restart app with PM2 ─────────────────────────────────────
echo "[7/7] Starting ZTS app with PM2..."
pm2 stop $APP_NAME 2>/dev/null || true
pm2 delete $APP_NAME 2>/dev/null || true
pm2 start server.js --name $APP_NAME --cwd "$APP_DIR"
pm2 save
pm2 startup systemd -u root --hp /root | tail -1 | bash 2>/dev/null || true
echo "  → App started ✓"

# ─── Log Deployment to Database ─────────────────────────────────────────────
echo ""
echo "Logging deployment to database..."
node -e "
const db = require('./db');
(async () => {
  try {
    await db.query(
      \`INSERT INTO deployments (deployed_by, git_commit, git_branch, status, vps_ip, notes)
       VALUES (\$1, \$2, \$3, \$4, \$5, \$6)\`,
      ['root', '$GIT_COMMIT', '$GIT_BRANCH', 'success', '$VPS_IP', 'Deployed via deploy.sh']
    );
    console.log('  → Deployment logged to database ✓');
    process.exit(0);
  } catch(e) {
    console.log('  ⚠️  Could not log to DB:', e.message);
    process.exit(0);
  }
})();
" 2>/dev/null || echo "  ⚠️  DB log skipped (DB not ready yet)"

# ─── Done! ───────────────────────────────────────────────────────────────────
echo ""
echo "================================================"
echo "  ✅  DEPLOYMENT COMPLETE!"
echo "================================================"
echo "  App URL  : http://$VPS_IP"
echo "  Commit   : $GIT_COMMIT ($GIT_BRANCH)"
echo ""
echo "  Useful commands:"
echo "    pm2 logs $APP_NAME        → view logs"
echo "    pm2 restart $APP_NAME     → restart"
echo "    pm2 status                → check status"
echo "    git -C $APP_DIR log --oneline -5  → recent commits"
echo ""
