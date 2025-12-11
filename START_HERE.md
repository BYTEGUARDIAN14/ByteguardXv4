# 🚀 ByteGuardX - Quick Start Guide

## **Single-Click Startup Options**

### **Option 1: Node.js Script (Recommended)**
```bash
npm run start
```
**OR**
```bash
node start-byteguardx.js
```

### **Option 2: PowerShell Script (Windows)**
```powershell
.\start-byteguardx.ps1
```

### **Option 3: Batch File (Windows)**
```cmd
start-byteguardx.bat
```

---

## **🎯 Single Access Point**

After running any startup script above, ByteGuardX will be available at:

### **🌐 Main Application**
**http://localhost:3000**

This single link gives you access to:
- ✅ **Complete ByteGuardX Application**
- ✅ **Dashboard & Analytics**
- ✅ **Security Scanning**
- ✅ **User Management**
- ✅ **Real-time Monitoring**
- ✅ **All Enterprise Features**

---

## **🧪 Test Pages (Optional)**

- **Connection Test**: http://localhost:3000/test-connection.html
- **Signup Test**: http://localhost:3000/test-signup.html
- **CSRF Test**: http://localhost:3000/test-csrf.html

---

## **⚙️ What Happens Automatically**

1. **Backend API Server** starts on port 5000
2. **Frontend Development Server** starts on port 3000
3. **Browser opens automatically** to http://localhost:3000
4. **All services are health-checked** before opening
5. **CSRF protection is disabled** for development ease

---

## **🛑 How to Stop**

Press **Ctrl+C** in the terminal where you started the application.

All servers will be stopped automatically.

---

## **📊 System Status**

### **Backend API**
- **URL**: http://localhost:5000
- **Health Check**: http://localhost:5000/health
- **Status**: ✅ Running with all optimizations

### **Frontend App**
- **URL**: http://localhost:3000
- **Framework**: React + Vite
- **Status**: ✅ Running with hot reload

### **Features Active**
- ⚡ **60fps Animations** with adaptive quality
- 📊 **Real-time Performance Monitoring**
- ♿ **Full Accessibility Support** (WCAG 2.1 AA)
- 🔄 **Offline-First Architecture**
- 🛡️ **Advanced Error Handling**
- 📱 **Responsive Design**
- 🎯 **Virtual Scrolling** for large datasets
- 🖼️ **Progressive Image Loading**
- 💀 **Skeleton Loaders**
- 🏪 **Advanced State Management**

---

## **🔧 Manual Startup (If Needed)**

### **Backend Only**
```bash
python -m byteguardx.api.app
```

### **Frontend Only**
```bash
npm run dev
```

---

## **🚨 Troubleshooting**

### **Port Already in Use**
The startup scripts automatically detect and stop conflicting processes.

### **Backend Won't Start**
1. Check Python dependencies: `pip install -r requirements.txt`
2. Check Python version: `python --version` (3.8+ required)

### **Frontend Won't Start**
1. Install dependencies: `npm install`
2. Check Node version: `node --version` (16+ required)

### **Browser Doesn't Open**
Manually navigate to: **http://localhost:3000**

---

## **🎉 Ready to Test!**

Once started, you can:

1. **Sign Up**: Create a new account (CSRF disabled for dev)
2. **Dashboard**: View security metrics and analytics
3. **Scan Files**: Upload and scan for vulnerabilities
4. **Monitor Performance**: Real-time system monitoring
5. **Test Features**: All enterprise-grade functionality

---

## **📱 Mobile Testing**

The application is fully responsive. Test on mobile by:
1. Find your local IP: `ipconfig` (Windows) or `ifconfig` (Mac/Linux)
2. Access from mobile: `http://YOUR_IP:3000`

---

## **🔥 Enterprise Features Available**

- 🛡️ **AI-Powered Vulnerability Scanning**
- 📊 **Real-time Security Dashboard**
- 🔍 **Advanced Threat Detection**
- 📈 **Performance Analytics**
- 👥 **User Management & RBAC**
- 🔄 **Automated Incident Response**
- 📱 **Mobile-Responsive Design**
- ♿ **Full Accessibility Support**
- 🌐 **Offline-First Architecture**
- ⚡ **60fps Smooth Animations**

---

**🚀 Start with: `npm run start` and visit http://localhost:3000**
