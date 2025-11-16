#!/bin/bash
# deploy.sh - Deploy ZTS to VPS
# Run this on the VPS after uploading the project files

echo "--- ZTS Deployment Script ---"

# 1. Install Node.js 20
echo "Installing Node.js..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# 2. Install PM2 (process manager)
echo "Installing PM2..."
npm install -g pm2

# 3. Install Nginx
echo "Installing Nginx..."
apt-get install -y nginx

# 4. Go to project directory
cd /root/zts-app

# 5. Install dependencies
echo "Installing project dependencies..."
npm install

# 6. Configure Nginx
echo "Configuring Nginx..."
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

# Enable the site
ln -sf /etc/nginx/sites-available/zts /etc/nginx/sites-enabled/zts
rm -f /etc/nginx/sites-enabled/default

# Test and restart Nginx
nginx -t && systemctl restart nginx

# 7. Start the app with PM2
echo "Starting ZTS app..."
pm2 stop zts 2>/dev/null
pm2 start server.js --name zts
pm2 save
pm2 startup systemd -u root --hp /root

echo ""
echo "--- Deployment Complete ---"
echo "ZTS is running at http://212.227.39.216"
echo ""
echo "Useful commands:"
echo "  pm2 logs zts     - view app logs"
echo "  pm2 restart zts  - restart app"
echo "  pm2 stop zts     - stop app"
echo ""
