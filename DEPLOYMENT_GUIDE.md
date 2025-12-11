# 🚀 ByteGuardX Authentication System Deployment Guide

## Overview

This guide covers the complete deployment of the ByteGuardX authentication system for both development and production environments.

## 📋 Prerequisites

### System Requirements
- **Python**: 3.8+ with pip
- **Node.js**: 16+ with npm
- **Database**: PostgreSQL 12+ (production) or SQLite (development)
- **Redis**: 6+ (optional, for session storage)
- **SSL Certificate**: Required for production

### Development Tools
- Git
- Docker (optional)
- VS Code or similar IDE

## ✅ Quick Start (Development)

### 1. Start Backend
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export JWT_SECRET_KEY="dev-secret-key"
export FLASK_ENV="development"
export ALLOWED_ORIGINS="http://localhost:3000"

# Start server
python run_server.py
```

### 2. Start Frontend
```bash
# Install dependencies
npm install

# Set API URL
echo "VITE_API_URL=http://localhost:5000" > .env

# Start development server
npm run dev
```

### 3. Test Authentication
```bash
python test_auth.py
```

## 🛠️ Development Setup

### 1. Clone Repository
```bash
git clone https://github.com/your-org/byteguardx.git
cd byteguardx
```

### 2. Backend Setup

#### Install Python Dependencies
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### Environment Configuration
Create `.env` file in project root:
```bash
# Development Environment
FLASK_ENV=development
FLASK_DEBUG=1
JWT_SECRET_KEY=dev-secret-key-change-in-production
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
ENABLE_2FA=false
DATABASE_URL=sqlite:///byteguardx_dev.db

# Optional: PostgreSQL for development
# DATABASE_URL=postgresql://username:password@localhost:5432/byteguardx_dev

# Optional: Redis for session storage
# REDIS_URL=redis://localhost:6379/0
```

#### Initialize Database
```bash
python -c "
from byteguardx.database.connection_pool import init_db
init_db()
print('Database initialized successfully!')
"
```

#### Start Development Server
```bash
python run_server.py
```

### 3. Frontend Setup

#### Install Dependencies
```bash
npm install
```

#### Environment Configuration
Create `.env` file in project root:
```bash
VITE_API_URL=http://localhost:5000
```

#### Start Development Server
```bash
npm run dev
```

### 4. Verify Installation
```bash
# Test authentication endpoints
python test_auth.py

# Expected output:
# ✅ All tests passed! Authentication system is working correctly.
```

## 🌐 Production Deployment

### 1. Server Preparation

#### System Updates
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv nginx postgresql redis-server
```

#### Create Application User
```bash
sudo useradd -m -s /bin/bash byteguardx
sudo usermod -aG sudo byteguardx
```

### 2. Database Setup (PostgreSQL)

#### Install and Configure PostgreSQL
```bash
sudo -u postgres psql
```

```sql
CREATE DATABASE byteguardx_prod;
CREATE USER byteguardx_user WITH PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE byteguardx_prod TO byteguardx_user;
\q
```

### 3. Application Deployment

#### Clone and Setup Application
```bash
sudo su - byteguardx
git clone https://github.com/your-org/byteguardx.git
cd byteguardx

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install gunicorn psycopg2-binary
```

#### Production Environment Configuration
Create `/home/byteguardx/byteguardx/.env`:
```bash
# Production Environment
FLASK_ENV=production
FLASK_DEBUG=0
JWT_SECRET_KEY=your-super-secure-jwt-secret-key-here
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
ENABLE_2FA=true
DATABASE_URL=postgresql://byteguardx_user:secure_password_here@localhost:5432/byteguardx_prod
REDIS_URL=redis://localhost:6379/0

# Security Settings
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Strict
```

#### Initialize Production Database
```bash
python -c "
from byteguardx.database.connection_pool import init_db
init_db()
print('Production database initialized!')
"
```

### 4. Frontend Build and Deployment

#### Build Production Frontend
```bash
# Install dependencies
npm ci --production

# Create production environment file
echo "VITE_API_URL=https://api.yourdomain.com" > .env.production

# Build for production
npm run build
```

#### Deploy to Web Server
```bash
# Copy build files to web server directory
sudo cp -r dist/* /var/www/byteguardx/
sudo chown -R www-data:www-data /var/www/byteguardx/
```

### 5. Web Server Configuration

#### Nginx Configuration
Create `/etc/nginx/sites-available/byteguardx`:
```nginx
# Frontend (React App)
server {
    listen 80;
    listen [::]:80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL Configuration
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Frontend
    location / {
        root /var/www/byteguardx;
        index index.html;
        try_files $uri $uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}

# Backend API
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.yourdomain.com;

    # SSL Configuration (same as above)
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # API Proxy
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Rate limiting
        limit_req zone=api burst=20 nodelay;
    }
}

# Rate limiting configuration
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
}
```

#### Enable Site
```bash
sudo ln -s /etc/nginx/sites-available/byteguardx /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 6. Process Management

#### Create Systemd Service
Create `/etc/systemd/system/byteguardx.service`:
```ini
[Unit]
Description=ByteGuardX Authentication API
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=byteguardx
Group=byteguardx
WorkingDirectory=/home/byteguardx/byteguardx
Environment=PATH=/home/byteguardx/byteguardx/venv/bin
ExecStart=/home/byteguardx/byteguardx/venv/bin/gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 4 \
    --worker-class gevent \
    --worker-connections 1000 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --timeout 30 \
    --keep-alive 2 \
    --log-level info \
    --access-logfile /var/log/byteguardx/access.log \
    --error-logfile /var/log/byteguardx/error.log \
    "byteguardx.api.security_enhanced_app:create_security_enhanced_app()"

Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

#### Create Log Directory
```bash
sudo mkdir -p /var/log/byteguardx
sudo chown byteguardx:byteguardx /var/log/byteguardx
```

#### Start and Enable Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable byteguardx
sudo systemctl start byteguardx
sudo systemctl status byteguardx
```

### 7. SSL Certificate Setup

#### Using Let's Encrypt (Certbot)
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com -d api.yourdomain.com
```

#### Auto-renewal
```bash
sudo crontab -e
# Add this line:
0 12 * * * /usr/bin/certbot renew --quiet
```

## 🔒 Security Hardening

### 1. Firewall Configuration
```bash
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 5000/tcp  # Block direct API access
```

### 2. Fail2Ban Setup
```bash
sudo apt install fail2ban

# Create custom jail for ByteGuardX
sudo tee /etc/fail2ban/jail.d/byteguardx.conf << EOF
[byteguardx-auth]
enabled = true
port = http,https
filter = byteguardx-auth
logpath = /var/log/byteguardx/access.log
maxretry = 5
bantime = 3600
findtime = 600
EOF
```

### 3. Database Security
```bash
# PostgreSQL security
sudo -u postgres psql
ALTER USER byteguardx_user SET default_transaction_isolation TO 'read committed';
ALTER USER byteguardx_user SET timezone TO 'UTC';
\q

# Backup configuration
sudo crontab -e
# Add daily backup:
0 2 * * * pg_dump byteguardx_prod | gzip > /backup/byteguardx_$(date +\%Y\%m\%d).sql.gz
```

## 📊 Monitoring and Maintenance

### 1. Log Monitoring
```bash
# View application logs
sudo journalctl -u byteguardx -f

# View access logs
sudo tail -f /var/log/byteguardx/access.log

# View error logs
sudo tail -f /var/log/byteguardx/error.log
```

### 2. Health Checks
```bash
# API health check
curl -f https://api.yourdomain.com/health || echo "API is down!"

# Database connection check
sudo -u byteguardx psql $DATABASE_URL -c "SELECT 1;" || echo "Database is down!"
```

### 3. Performance Monitoring
- Set up monitoring with tools like Prometheus + Grafana
- Monitor key metrics: response times, error rates, authentication success/failure rates
- Set up alerts for critical issues

## 🔄 Updates and Maintenance

### 1. Application Updates
```bash
# Backup database
pg_dump byteguardx_prod > backup_$(date +%Y%m%d).sql

# Update application
sudo su - byteguardx
cd byteguardx
git pull origin main
source venv/bin/activate
pip install -r requirements.txt

# Restart service
sudo systemctl restart byteguardx
```

### 2. Security Updates
```bash
# System updates
sudo apt update && sudo apt upgrade -y

# Python package updates
pip list --outdated
pip install --upgrade package_name

# Node.js updates
npm audit
npm update
```

## 🆘 Troubleshooting

### Common Issues

#### 1. Authentication Failures
- Check JWT secret key configuration
- Verify database connectivity
- Review audit logs for failed attempts

#### 2. CORS Issues
- Verify ALLOWED_ORIGINS environment variable
- Check Nginx proxy headers
- Ensure frontend URL matches allowed origins

#### 3. Database Connection Issues
- Check PostgreSQL service status
- Verify connection string
- Check firewall rules

#### 4. SSL Certificate Issues
- Verify certificate validity
- Check Nginx SSL configuration
- Ensure proper certificate chain

### Log Analysis
```bash
# Check authentication failures
grep "LOGIN_FAILURE" /var/log/byteguardx/audit.log

# Monitor rate limiting
grep "rate_limit" /var/log/nginx/access.log

# Check system errors
sudo journalctl -u byteguardx --since "1 hour ago"
```

## 📞 Support

For deployment issues:
1. Check the troubleshooting section above
2. Review application logs
3. Consult the authentication implementation documentation
4. Contact the development team

---

**Last Updated**: 2025-01-08  
**Version**: 1.0.0  
**Status**: Production Ready
