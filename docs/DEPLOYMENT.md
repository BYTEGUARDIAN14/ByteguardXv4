# ByteGuardX Deployment Guide

This guide covers all deployment options for ByteGuardX, from local development to enterprise production environments.

## 🚀 Quick Start (Local Development)

### Prerequisites
- Python 3.8+
- Node.js 18+
- Git

### One-Command Setup
```bash
git clone https://github.com/byteguardx/byteguardx.git
cd byteguardx
python run.py
```

This will:
1. Install Python dependencies
2. Install Node.js dependencies
3. Start backend API on port 5000
4. Start frontend on port 3000
5. Open browser to http://localhost:3000

## 🐳 Docker Deployment

### Development with Docker Compose
```bash
# Clone repository
git clone https://github.com/byteguardx/byteguardx.git
cd byteguardx

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production Docker Compose
```bash
# Use production configuration
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# With SSL/TLS
docker-compose --profile production up -d
```

## ☸️ Kubernetes Deployment

### Prerequisites
- Kubernetes cluster (1.20+)
- kubectl configured
- Helm 3.x (optional)

### Quick Deploy
```bash
# Apply all manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n byteguardx

# Get service URLs
kubectl get ingress -n byteguardx
```

### Helm Deployment
```bash
# Add ByteGuardX Helm repository
helm repo add byteguardx https://charts.byteguardx.com
helm repo update

# Install with default values
helm install byteguardx byteguardx/byteguardx

# Install with custom values
helm install byteguardx byteguardx/byteguardx -f values.yaml
```

### Custom Values (values.yaml)
```yaml
# ByteGuardX Helm Values
replicaCount:
  backend: 3
  frontend: 2

image:
  repository: byteguardx
  tag: "latest"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: byteguardx.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: byteguardx-tls
      hosts:
        - byteguardx.example.com

persistence:
  enabled: true
  storageClass: "fast-ssd"
  size: 10Gi

resources:
  backend:
    limits:
      cpu: 500m
      memory: 1Gi
    requests:
      cpu: 250m
      memory: 512Mi
  frontend:
    limits:
      cpu: 200m
      memory: 512Mi
    requests:
      cpu: 100m
      memory: 256Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
```

## 🌩️ Cloud Deployments

### AWS EKS
```bash
# Create EKS cluster
eksctl create cluster --name byteguardx --region us-west-2

# Deploy ByteGuardX
kubectl apply -f k8s/

# Setup Load Balancer
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/aws/deploy.yaml
```

### Google GKE
```bash
# Create GKE cluster
gcloud container clusters create byteguardx \
  --zone us-central1-a \
  --num-nodes 3

# Get credentials
gcloud container clusters get-credentials byteguardx --zone us-central1-a

# Deploy
kubectl apply -f k8s/
```

### Azure AKS
```bash
# Create resource group
az group create --name byteguardx-rg --location eastus

# Create AKS cluster
az aks create \
  --resource-group byteguardx-rg \
  --name byteguardx \
  --node-count 3 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Get credentials
az aks get-credentials --resource-group byteguardx-rg --name byteguardx

# Deploy
kubectl apply -f k8s/
```

## 🔧 Configuration

### Environment Variables

#### Backend Configuration
```bash
# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here

# Database
DATABASE_URL=postgresql://user:pass@host:5432/byteguardx

# Redis (optional)
REDIS_URL=redis://localhost:6379

# API Settings
ALLOWED_ORIGINS=https://app.byteguardx.com,https://byteguardx.com
MAX_CONTENT_LENGTH=52428800  # 50MB
UPLOAD_FOLDER=/tmp/byteguardx_uploads

# Features
ENABLE_ANALYTICS=true
ENABLE_WEBHOOKS=true
ENABLE_RATE_LIMITING=true

# External Services
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
JIRA_SERVER_URL=https://your-company.atlassian.net
JIRA_USERNAME=your-email@company.com
JIRA_API_TOKEN=your-api-token
```

#### Frontend Configuration
```bash
# API
VITE_API_URL=https://api.byteguardx.com

# App Info
VITE_APP_NAME=ByteGuardX
VITE_APP_VERSION=1.0.0

# Features
VITE_ENABLE_AUTH=true
VITE_ENABLE_ANALYTICS=false
VITE_ENABLE_DEBUG=false

# External Links
VITE_GITHUB_URL=https://github.com/byteguardx/byteguardx
VITE_DOCS_URL=https://docs.byteguardx.com
VITE_SUPPORT_EMAIL=support@byteguardx.com
```

### Database Setup

#### PostgreSQL (Recommended)
```sql
-- Create database
CREATE DATABASE byteguardx;

-- Create user
CREATE USER byteguardx WITH PASSWORD 'secure_password';

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE byteguardx TO byteguardx;

-- Connect and create tables
\c byteguardx;

-- Tables will be created automatically on first run
```

#### SQLite (Development)
```bash
# SQLite database will be created automatically
# Location: ./data/byteguardx.db
```

### SSL/TLS Setup

#### Let's Encrypt with Cert-Manager
```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@byteguardx.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

## 📊 Monitoring & Observability

### Prometheus & Grafana
```bash
# Install Prometheus Operator
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack

# Import ByteGuardX dashboard
kubectl apply -f monitoring/grafana-dashboard.yaml
```

### Logging with ELK Stack
```bash
# Install Elasticsearch
helm repo add elastic https://helm.elastic.co
helm install elasticsearch elastic/elasticsearch

# Install Kibana
helm install kibana elastic/kibana

# Install Filebeat
helm install filebeat elastic/filebeat
```

### Health Checks
```bash
# Backend health
curl https://api.byteguardx.com/health

# Frontend health
curl https://app.byteguardx.com/

# Kubernetes health
kubectl get pods -n byteguardx
kubectl describe pod <pod-name> -n byteguardx
```

## 🔐 Security Considerations

### Network Security
- Use TLS 1.3 for all communications
- Implement proper firewall rules
- Use VPC/private networks
- Enable DDoS protection

### Authentication & Authorization
- Use strong JWT secrets
- Implement proper RBAC
- Enable MFA for admin accounts
- Regular security audits

### Data Protection
- Encrypt data at rest
- Use secure backup strategies
- Implement data retention policies
- GDPR/CCPA compliance

### Container Security
```bash
# Scan images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image byteguardx/backend:latest

# Use non-root users
# Implement resource limits
# Regular security updates
```

## 🚨 Troubleshooting

### Common Issues

#### Backend Won't Start
```bash
# Check logs
docker logs byteguardx-backend
kubectl logs -f deployment/byteguardx-backend -n byteguardx

# Common fixes
- Check environment variables
- Verify database connection
- Check file permissions
- Ensure ports are available
```

#### Frontend Build Fails
```bash
# Clear cache
npm cache clean --force
rm -rf node_modules package-lock.json
npm install

# Check Node.js version
node --version  # Should be 18+
```

#### Database Connection Issues
```bash
# Test connection
psql -h localhost -U byteguardx -d byteguardx

# Check network connectivity
telnet database-host 5432

# Verify credentials
echo $DATABASE_URL
```

#### Performance Issues
```bash
# Check resource usage
kubectl top pods -n byteguardx
kubectl describe hpa -n byteguardx

# Scale manually
kubectl scale deployment byteguardx-backend --replicas=5 -n byteguardx
```

### Debug Mode
```bash
# Enable debug logging
export FLASK_ENV=development
export LOG_LEVEL=DEBUG

# Frontend debug
export VITE_ENABLE_DEBUG=true
```

## 📈 Scaling

### Horizontal Scaling
```yaml
# HPA configuration
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: byteguardx-backend-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: byteguardx-backend
  minReplicas: 2
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Vertical Scaling
```bash
# Update resource limits
kubectl patch deployment byteguardx-backend -n byteguardx -p '{"spec":{"template":{"spec":{"containers":[{"name":"byteguardx-backend","resources":{"limits":{"cpu":"1000m","memory":"2Gi"}}}]}}}}'
```

## 🔄 CI/CD Integration

### GitHub Actions
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Build and Push Images
      run: |
        docker build -t byteguardx/backend:${{ github.sha }} -f Dockerfile.backend .
        docker build -t byteguardx/frontend:${{ github.sha }} -f Dockerfile.frontend .
        docker push byteguardx/backend:${{ github.sha }}
        docker push byteguardx/frontend:${{ github.sha }}
    
    - name: Deploy to Kubernetes
      run: |
        kubectl set image deployment/byteguardx-backend byteguardx-backend=byteguardx/backend:${{ github.sha }} -n byteguardx
        kubectl set image deployment/byteguardx-frontend byteguardx-frontend=byteguardx/frontend:${{ github.sha }} -n byteguardx
```

## 📞 Support

### Getting Help
- **Documentation**: https://docs.byteguardx.com
- **GitHub Issues**: https://github.com/byteguardx/byteguardx/issues
- **Discord**: https://discord.gg/byteguardx
- **Email**: support@byteguardx.com

### Enterprise Support
- 24/7 support available
- Dedicated Slack channel
- Custom deployment assistance
- SLA guarantees

Contact: enterprise@byteguardx.com
