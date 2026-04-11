#!/bin/bash

set -e  # Exit immediately if any command fails

REPO_URL="https://github.com/rajanchand/zerotrustsecurity-demo.git"
APP_DIR="/root/zts-web"
APP_NAME="zts"
VPS_IP=$(curl -s ifconfig.me)

echo ""
echo "================================================"
echo "   🚀 ZTS - Optimized Deployment"
echo "================================================"
echo "  Repo : $REPO_URL"
echo "  Dir  : $APP_DIR"
echo "  IP   : $VPS_IP"
echo ""

# ─── Step 1 & 2: Environment Readiness ─────────────────────
# (Fast checks)
if ! command -v node &> /dev/null || ! command -v pm2 &> /dev/null; then
  echo "[1/7] Bootstrapping Node.js/PM2..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
  npm install -g pm2
else
  echo "[1/2] Environment ready (Node $(node -v)) ✓"
fi

# ─── Step 3: Fast Git Fetch & Reset ──────────────────────────
echo "[3/7] Syncing code from GitHub..."
if [ ! -d "$APP_DIR/.git" ]; then
  echo "  → Cloning fresh..."
  rm -rf "$APP_DIR"
  git clone "$REPO_URL" "$APP_DIR"
  cd "$APP_DIR"
else
  cd "$APP_DIR"
  git fetch origin main
  git reset --hard origin/main
fi

GIT_COMMIT=$(git rev-parse --short HEAD)
echo "  → Latest commit: $GIT_COMMIT ✓"

# ─── Step 4: Smart NPM Install ───────────────────────────────
# Only run if package-lock.json has changed
LOCK_HASH=$(md5sum package-lock.json | awk '{ print $1 }')
if [ ! -f .last_install ] || [ "$(cat .last_install)" != "$LOCK_HASH" ]; then
    echo "[4/7] package-lock.json changed. Installing dependencies..."
    npm install --omit=dev
    echo "$LOCK_HASH" > .last_install
else
    echo "[4/7] No dependency changes. Skipping npm install ⚡"
fi

# ─── Step 5: Environment Check ───────────────────────────────
if [ ! -f "$APP_DIR/.env" ]; then
  echo "  ⚠️ Error: No .env file found in $APP_DIR"
  exit 1
fi

# ─── Step 6: Config Optimization (Nginx) ────────────────────
# Only reload if the config changed
NGINX_CONF="/etc/nginx/sites-available/zts"
TEMP_CONF="/tmp/zts_nginx.conf"

DOMAIN="${DOMAIN:-zero-trust-security.org}"

cat > "$TEMP_CONF" << EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        #  Fix: Forward the proto from Cloudflare (Flexible SSL)
        # Standard \$scheme is 'http' locally, which blocks 'Secure' cookies.
        # We must tell Node that the outer connection is 'https'.
        proxy_set_header X-Forwarded-Proto \$http_x_forwarded_proto;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# Only overwrite Nginx config if we really need to (if SSL isn't configured yet)
if [ ! -f "$NGINX_CONF" ] || ! grep -q "ssl_certificate" "$NGINX_CONF"; then
    if ! cmp -s "$TEMP_CONF" "$NGINX_CONF"; then
        echo "[6/7] Updating Nginx config..."
        cp "$TEMP_CONF" "$NGINX_CONF"
        ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/zts
        rm -f /etc/nginx/sites-enabled/default
        nginx -t && systemctl restart nginx
    fi
else
    echo "[6/7] Nginx SSL config intact. Skipping HTTP-only overwrite ✓"
fi

# ─── Step 6.5: Automated SSL with Certbot ───────────────────
if ! command -v certbot &> /dev/null; then
  echo "[6.5/7] Installing Certbot for Let's Encrypt..."
  sudo apt-get update
  sudo apt-get install -y certbot python3-certbot-nginx
fi

if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    echo "[6.6/7] Requesting Let's Encrypt SSL certificate for $DOMAIN..."
    certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos -m admin@$DOMAIN || true
else
    echo "[6.6/7] SSL Certificates already exist. Ensuring Nginx is configured..."
    # If deploy.sh overwrote the nginx file with the base HTTP config, re-inject the SSL block automatically
    if ! grep -q "ssl_certificate" "$NGINX_CONF"; then
        echo "  → Re-injecting missing SSL configuration blocks via Certbot..."
        certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --redirect --reinstall || true
    else
        echo "  → SSL config is fully intact ✓"
    fi
fi
# ─── Step 7: Final PM2 Launch with Port Safety ──────────────
echo "[7/7] Launching application..."

# 💥 Hard kill any process using port 3000
echo "  → Clearing port 3000 (EADDRINUSE safety)..."
fuser -k 3000/tcp 2>/dev/null || true

# Cleanup any alternate process names
pm2 delete zts-live 2>/dev/null || true
pm2 delete zts 2>/dev/null || true

# Start fresh
pm2 start server.js --name $APP_NAME --cwd "$APP_DIR"
pm2 save

echo ""
echo "================================================"
echo "  ✅  DEPLOYED IN RECORD TIME!"
echo "================================================"
echo "  App URL  : http://$VPS_IP"
echo "  Commit   : $GIT_COMMIT"
echo ""

# ─── Step 8: Send Slack Notification ──────────────────────────
if [ -f "$APP_DIR/.env" ]; then
    # Manually extract SLACK_WEBHOOK_URL to avoid side effects of blindly sourcing
    SLACK_URL=$(grep "^SLACK_DEPLOY_WEBHOOK_URL=" "$APP_DIR/.env" | cut -d '=' -f2- | tr -d '"' | tr -d "'" | tr -d '\r' | tr -d ' ' | xargs)
    
    # If a specific deploy webhook doesn't exist, fall back to the global security one
    if [ -z "$SLACK_URL" ]; then
        SLACK_URL=$(grep "^SLACK_WEBHOOK_URL=" "$APP_DIR/.env" | cut -d '=' -f2- | tr -d '"' | tr -d "'" | tr -d '\r' | tr -d ' ' | xargs)
    fi

    if [ -n "$SLACK_URL" ]; then
        echo "  → Sending Slack deployment alert..."
        curl -s -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚀 *ZTS Deployed Successfully*\nNew code (Commit: \`$GIT_COMMIT\`) was just pulled to the VPS and is now live!\"}" \
        "$SLACK_URL" > /dev/null || true
    fi
fi
