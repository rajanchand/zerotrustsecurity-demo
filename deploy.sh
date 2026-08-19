#!/bin/bash

set -e  # Exit immediately if any command fails

REPO_URL="https://github.com/rajanchand/zerotrustsecurity-demo.git"
APP_DIR="/root/zts-web"
APP_NAME="zts"
VPS_IP=$(curl -s ifconfig.me)

echo ""
echo "================================================"
echo "   ZTS - Deployment"
echo "================================================"
echo "  Repo : $REPO_URL"
echo "  Dir  : $APP_DIR"
echo "  IP   : $VPS_IP"
echo ""

# Step 1: Environment check
if ! command -v node &> /dev/null || ! command -v pm2 &> /dev/null || ! command -v nginx &> /dev/null; then
  echo "[1/7] Setting up Node.js, PM2, and Nginx..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs nginx
  npm install -g pm2
else
  echo "[1/7] Environment ready (Node $(node -v))"
fi

# Step 3: Git fetch and reset
echo "[3/7] Syncing code from GitHub..."
if [ ! -d "$APP_DIR/.git" ]; then
  echo "  -> Cloning fresh..."
  rm -rf "$APP_DIR"
  git clone "$REPO_URL" "$APP_DIR"
  cd "$APP_DIR"
else
  cd "$APP_DIR"
  git fetch origin main
  git reset --hard origin/main
fi

GIT_COMMIT=$(git rev-parse --short HEAD)
echo "  -> Latest commit: $GIT_COMMIT"

# Step 4: NPM install (only if dependencies changed)
LOCK_HASH=$(md5sum package-lock.json | awk '{ print $1 }')
if [ ! -f .last_install ] || [ "$(cat .last_install)" != "$LOCK_HASH" ]; then
    echo "[4/7] package-lock.json changed. Installing dependencies..."
    npm install --omit=dev
    echo "$LOCK_HASH" > .last_install
else
    echo "[4/7] No dependency changes. Skipping npm install."
fi

# Step 5: Environment file check & auto-creation
if [ ! -f "$APP_DIR/.env" ]; then
  echo "[5/7] Creating default production .env file..."
  SECRET_HEX=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" 2>/dev/null || echo "zts-production-session-secret-$(date +%s)")
  cat > "$APP_DIR/.env" <<EOF
PORT=3000
NODE_ENV=production
SESSION_SECRET=$SECRET_HEX
EOF
  echo "  -> Created .env successfully."
else
  echo "[5/7] Environment file (.env) exists."
fi

# Step 6: Nginx config
NGINX_CONF="/etc/nginx/sites-available/zts"
TEMP_CONF="/tmp/zts_nginx.conf"

DOMAIN="${DOMAIN:-zero-trust-security.org}"

cat > "$TEMP_CONF" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN www.$DOMAIN 212.227.39.216 _;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# Only overwrite Nginx config if SSL isnt configured yet
if [ ! -f "$NGINX_CONF" ] || ! grep -q "ssl_certificate" "$NGINX_CONF"; then
    if ! cmp -s "$TEMP_CONF" "$NGINX_CONF"; then
        echo "[6/7] Updating Nginx config..."
        cp "$TEMP_CONF" "$NGINX_CONF"
        ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/zts
        rm -f /etc/nginx/sites-enabled/default
        nginx -t && systemctl restart nginx
    fi
else
    echo "[6/7] Nginx SSL config intact. Skipping."
fi

# Step 6.5: SSL with Certbot
if ! command -v certbot &> /dev/null; then
  echo "[6.5/7] Installing Certbot for Let's Encrypt..."
  sudo apt-get update
  sudo apt-get install -y certbot python3-certbot-nginx
fi

if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    echo "[6.6/7] Requesting Let's Encrypt SSL certificate for $DOMAIN..."
    certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos -m admin@$DOMAIN || true
else
    echo "[6.6/7] SSL Certificates already exist."
    # If deploy.sh overwrote the nginx file, re-inject SSL block
    if ! grep -q "ssl_certificate" "$NGINX_CONF"; then
        echo "  -> Re-injecting missing SSL configuration..."
        certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --redirect --reinstall || true
    else
        echo "  -> SSL config intact."
    fi
fi

# Step 7: Launch with PM2
echo "[7/7] Launching application..."

# Kill any process using port 3000
echo "  -> Clearing port 3000..."
fuser -k 3000/tcp 2>/dev/null || true

# Cleanup old process names
pm2 delete zts-live 2>/dev/null || true
pm2 delete zts 2>/dev/null || true

# Start fresh
pm2 start server.js --name $APP_NAME --cwd "$APP_DIR"
pm2 save

echo ""
echo "================================================"
echo "  DEPLOYED SUCCESSFULLY"
echo "================================================"
echo "  App URL  : http://$VPS_IP"
echo "  Commit   : $GIT_COMMIT"
echo ""

# Step 8: Slack notification
if [ -f "$APP_DIR/.env" ]; then
    SLACK_URL=$(grep "^SLACK_DEPLOY_WEBHOOK_URL=" "$APP_DIR/.env" | cut -d '=' -f2- | tr -d '"' | tr -d "'" | tr -d '\r' | tr -d ' ' | xargs)
    
    if [ -z "$SLACK_URL" ]; then
        SLACK_URL=$(grep "^SLACK_WEBHOOK_URL=" "$APP_DIR/.env" | cut -d '=' -f2- | tr -d '"' | tr -d "'" | tr -d '\r' | tr -d ' ' | xargs)
    fi

    if [ -n "$SLACK_URL" ]; then
        echo "  -> Sending Slack deployment alert..."
        curl -s -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"ZTS Deployed Successfully - Commit: \`$GIT_COMMIT\` is now live on the VPS.\"}" \
        "$SLACK_URL" > /dev/null || true
    fi
fi
