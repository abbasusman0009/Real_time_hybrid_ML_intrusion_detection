# Production Deployment Guide - RT-IDPS

## Overview

This guide helps you deploy the Real-Time Hybrid ML Intrusion Detection System to production on Render or similar cloud platforms.

## Security Fixes Applied

The following production-ready security fixes have been implemented:

### ✅ Fixed Issues

1. **Password Hashing** - Passwords now use `werkzeug.security` with PBKDF2-SHA256
2. **Environment Variables** - All sensitive config moved to environment variables
3. **Debug Mode** - Disabled by default (set via `FLASK_DEBUG` env var)
4. **Host Binding** - Changed from localhost to `0.0.0.0` for cloud deployment
5. **CORS Configuration** - Restricted CORS with configurable allowed origins
6. **Error Handling** - Added missing 500 error template
7. **Input Validation** - Login form now validates and sanitizes input
8. **Network Interface** - Made configurable via `NETWORK_INTERFACE` env var

---

## Pre-Deployment Checklist

### 1. Generate Secure Credentials

Run the credential generation script:

```bash
python setup_credentials.py
```

This will:
- Generate a secure `SECRET_KEY`
- Hash your admin password with PBKDF2-SHA256
- Create/update `.env` file with secure values

### 2. Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` with your values:

```env
SECRET_KEY=<generated-by-setup_credentials.py>
ADMIN_PASSWORD_HASH=<generated-by-setup_credentials.py>
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=False
ADMIN_USERNAME=admin
NETWORK_INTERFACE=eth0
CORS_ORIGINS=*
LOG_LEVEL=INFO
```

### 3. Verify Local Deployment

Test locally before pushing to Render:

```bash
# Activate virtual environment
source venv/bin/activate

# Load environment variables
export $(cat .env | grep -v '^#' | xargs)

# Run locally
python dashboard/app.py
```

Visit `http://localhost:5000` and test login with your credentials.

### 4. Push to GitHub

```bash
# Ensure .env is NOT in git (already in .gitignore)
git add .
git commit -m "Security hardening for production deployment"
git push origin main
```

---

## Render Deployment

### 1. Create Render Service

1. Go to [render.com](https://render.com)
2. Click **New +** → **Web Service**
3. Connect your GitHub repository
4. Select branch: `main`

### 2. Configure Service

- **Name**: `rt-idps-dashboard`
- **Environment**: Python 3
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn dashboard.app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 120`
- **Plan**: Free (or upgrade for better performance)

### 3. Set Environment Variables

In Render dashboard:

1. Go to **Environment** tab
2. Add these environment variables:

```
SECRET_KEY=<your-generated-key>
ADMIN_PASSWORD_HASH=<your-generated-hash>
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=False
ADMIN_USERNAME=admin
NETWORK_INTERFACE=eth0
CORS_ORIGINS=https://rt-idps-dashboard.onrender.com
LOG_LEVEL=INFO
```

### 4. Deploy

Click **Create Web Service** and monitor the deployment logs.

---

## Post-Deployment

### 1. Test the Application

- Navigate to your Render URL: `https://rt-idps-dashboard.onrender.com`
- Login with credentials you set up
- Verify all dashboard pages load correctly

### 2. Monitor Logs

Check Render dashboard **Logs** tab for errors.

### 3. Set Up Monitoring

Consider adding:
- Error tracking (Sentry)
- Log aggregation (LogDNA, Datadog)
- Performance monitoring (New Relic)

---

## Important Considerations

### Real-Time Detection on Render

⚠️ **Packet capture is unavailable on Render** due to container network restrictions.

The dashboard will:
- ✅ Display sample data and statistics
- ✅ Allow manual IP blocking (simulated)
- ✅ Show alerts and logs
- ❌ NOT capture live network traffic
- ❌ NOT perform real-time packet inspection

**This is expected and working as designed.**

### Free Tier Limitations

- App goes to sleep after 15 minutes of inactivity
- No persistent file storage
- Limited CPU/memory resources
- Upgrade to **Pro Plan** for production use

### Database Integration (Future)

For production, consider adding:
- PostgreSQL for persistent storage
- Redis for caching and sessions
- S3/Render Disks for model/log storage

---

## Troubleshooting

### Login Not Working

1. Verify `ADMIN_PASSWORD_HASH` is set correctly in environment
2. Check logs for password hash validation errors
3. Regenerate credentials with `setup_credentials.py`

### CORS Errors

Update `CORS_ORIGINS` in environment variables:

```
CORS_ORIGINS=https://your-domain.com,https://api.your-domain.com
```

### Models Not Found

Ensure model files are committed to Git:

```bash
git status models/
# Should show: models/random_forest.pkl, models/kmeans.pkl, etc.
```

### Dashboard Shows Errors

Check Render logs:
1. Go to Render dashboard → **Logs** tab
2. Search for error messages
3. Common issues:
   - Missing environment variables
   - Incorrect password hash format
   - Port already in use

---

## Security Best Practices

1. **Rotate Secrets Regularly**
   - Change `SECRET_KEY` every 90 days
   - Rotate admin password regularly

2. **Monitor Access Logs**
   - Review authentication attempts
   - Watch for brute force attacks

3. **Update Dependencies**
   - Keep Python packages updated
   - Run `pip install --upgrade -r requirements.txt`

4. **HTTPS Only**
   - Render provides HTTPS by default
   - Enforce HTTPS in production

5. **Backup Configurations**
   - Save environment variables securely
   - Document all secrets in secure vault

---

## Useful Commands

### Generate New Credentials

```bash
python setup_credentials.py
```

### Test Configuration Locally

```bash
python -c "from utils.config import DASHBOARD_CONFIG, SECURITY_CONFIG; print(DASHBOARD_CONFIG); print(SECURITY_CONFIG)"
```

### Check Environment Variables

```bash
env | grep -E 'SECRET|PASSWORD|FLASK'
```

### Run with Production Settings

```bash
FLASK_DEBUG=False FLASK_HOST=0.0.0.0 python dashboard/app.py
```

---

## Support

For issues or questions:

1. Check Render logs for error details
2. Review this guide's Troubleshooting section
3. Consult [Render documentation](https://render.com/docs)
4. Review [Flask production deployment guide](https://flask.palletsprojects.com/en/2.3.x/deploying/)

---

## Next Steps

1. ✅ Run `python setup_credentials.py`
2. ✅ Create/update `.env` file
3. ✅ Test locally with production settings
4. ✅ Commit changes to Git
5. ✅ Deploy to Render
6. ✅ Monitor and verify deployment
7. ✅ Set up monitoring/alerting

**Happy deploying! 🚀**
