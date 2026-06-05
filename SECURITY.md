# Security Documentation - RT-IDPS

## Overview

This document outlines the security measures implemented in the Real-Time Hybrid ML Intrusion Detection System for production deployment.

## Security Architecture

### 1. Authentication & Authorization

#### Password Management
- **Algorithm**: PBKDF2-SHA256 (via werkzeug)
- **Hash Function**: SHA256 with salting
- **Setup**: Use `setup_credentials.py` to generate secure hashes
- **Storage**: Environment variable `ADMIN_PASSWORD_HASH`
- **Verification**: Uses `werkzeug.security.check_password_hash()`

#### Session Management
- **Session Timeout**: Configured via `SECURITY_CONFIG['session_lifetime']`
- **Default**: 1 hour (3600 seconds)
- **Persistence**: Sessions are server-side only
- **Security**: Session cookie with `session.permanent = True`

#### Login Protection
- **Input Validation**: Usernames and passwords are validated
- **Failed Attempts**: Logged with IP address
- **Rate Limiting**: Not implemented (TODO: Add Failban or similar)
- **Account Lockout**: Not implemented (TODO: Add after N failed attempts)

### 2. Encryption & Secrets

#### Secret Key
- **Purpose**: Used for session encryption and CSRF protection
- **Generation**: Use `setup_credentials.py` (generates 32-byte hex key)
- **Storage**: Environment variable `SECRET_KEY`
- **Rotation**: Recommended every 90 days
- **Policy**: Never hardcode, always use environment variables

#### Transport Security
- **HTTPS**: Enforced by Render (auto-generated SSL certificate)
- **Protocol**: TLS 1.2+ recommended
- **HSTS**: Not configured (TODO: Add `Strict-Transport-Security` header)

### 3. Access Control

#### Route Protection
- **Login Decorator**: `@login_required` on protected routes
- **API Decorator**: `@api_login_required` for JSON responses
- **Exception**: `/login` and `/` are publicly accessible

#### CORS Configuration
- **Default**: Restricted to configured origins
- **Env Variable**: `CORS_ORIGINS`
- **Format**: Comma-separated list of allowed origins
- **Example Production**: `https://rt-idps-dashboard.onrender.com`

### 4. HTTP Security Headers

Automatically added by `add_security_headers()` middleware:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Frame-Options` | SAMEORIGIN | Prevent clickjacking |
| `X-Content-Type-Options` | nosniff | Prevent MIME type sniffing |
| `X-XSS-Protection` | 1; mode=block | Enable XSS protection |
| `Content-Security-Policy` | Restrictive | Prevent code injection |
| `Referrer-Policy` | strict-origin-when-cross-origin | Control referrer info |
| `Permissions-Policy` | Restrictive | Disable unnecessary permissions |

### 5. Input Validation & Sanitization

#### Login Form
- Username: Stripped of whitespace, length checked
- Password: Length validated, no minimum enforced (TODO: Increase to 8+ chars)
- Validation: Occurs before credential verification
- Logging: Failed attempts logged with IP address

#### API Parameters
- Request arguments: Type-checked with default values
- CSV export: Properly escaped for safe file export
- Error handling: Generic messages to prevent information disclosure

### 6. Logging & Monitoring

#### Security Events Logged
- Successful logins (username, timestamp)
- Failed login attempts (username, IP address, timestamp)
- Detector service start/stop
- IP blocking operations
- Intrusion alerts
- System errors

#### Log Locations
- Application logs: `logs/dashboard.log`
- Detector logs: `logs/detector_service.log`
- Intrusion logs: `logs/intrusion_logs.csv`
- System logs: `logs/system.log`

#### Log Retention
- **Max File Size**: 10 MB
- **Backup Count**: 5 rotated files
- **Cleanup**: Logs not automatically deleted (TODO: Implement retention policy)

### 7. Error Handling

#### Exception Handling
- Generic error messages displayed to users
- Detailed errors logged server-side only
- Stack traces not exposed in production
- Custom error pages (404, 500) implemented

#### Sensitive Information Protection
- Database credentials not logged
- API keys never logged or displayed
- Password hashes never logged in plaintext
- User input sanitized in error messages

---

## Known Security Gaps & TODO Items

### High Priority

- [ ] **Rate Limiting**: Implement brute force protection on login
- [ ] **Account Lockout**: Lock account after N failed attempts
- [ ] **HSTS Header**: Add `Strict-Transport-Security` for HTTPS enforcement
- [ ] **Password Policy**: Enforce minimum 8 characters
- [ ] **Session Invalidation**: Clear old sessions on password change
- [ ] **Audit Logging**: Enhanced logging of all security-relevant events

### Medium Priority

- [ ] **Two-Factor Authentication**: Add TOTP/SMS 2FA
- [ ] **Password Expiration**: Force password changes periodically
- [ ] **IP Whitelisting**: Restrict access to specific IP ranges
- [ ] **Database Layer**: Add authentication database for multiple users
- [ ] **API Authentication**: Add API key-based auth for programmatic access
- [ ] **Encryption at Rest**: Encrypt sensitive configuration data

### Low Priority

- [ ] **Security Headers**: Add more restrictive CSP
- [ ] **Input Encoding**: Additional XSS prevention measures
- [ ] **SQL Injection Prevention**: Already implemented (using ORM-style queries)
- [ ] **CSRF Protection**: Enable Flask-WTF CSRF tokens
- [ ] **OWASP Compliance**: Full OWASP Top 10 audit

---

## Security Checklist for Deployment

### Before Going Live

- [ ] Run `python setup_credentials.py` and generate secure values
- [ ] Update `.env` with generated credentials (NEVER commit .env)
- [ ] Set `FLASK_DEBUG=False` in environment
- [ ] Set `FLASK_HOST=0.0.0.0` in environment
- [ ] Configure `CORS_ORIGINS` for your domain
- [ ] Test login with hashed password
- [ ] Verify all routes require authentication
- [ ] Check that error pages don't expose sensitive info
- [ ] Review Render environment variables are set
- [ ] Enable HTTPS (automatic on Render)

### After Deployment

- [ ] Monitor authentication logs for unusual activity
- [ ] Set up log aggregation (Sentry, LogDNA, etc.)
- [ ] Configure alerts for failed login attempts
- [ ] Schedule security audits (quarterly minimum)
- [ ] Keep dependencies updated (`pip install --upgrade -r requirements.txt`)
- [ ] Monitor for security advisories in dependencies
- [ ] Test disaster recovery procedures

### Ongoing Maintenance

- [ ] Rotate `SECRET_KEY` every 90 days
- [ ] Change admin password every 90 days
- [ ] Review access logs monthly
- [ ] Update Python and packages quarterly
- [ ] Monitor for CVEs in dependencies
- [ ] Conduct annual security audit

---

## Incident Response

### Suspected Breach

1. **Immediate Actions**
   - Disable compromised account
   - Rotate all secrets (`SECRET_KEY`, admin password)
   - Review recent access logs
   - Check for unauthorized model modifications

2. **Investigation**
   - Analyze authentication logs
   - Check for suspicious API calls
   - Review blocked IP logs
   - Examine file access timestamps

3. **Remediation**
   - Deploy security patches
   - Update all credentials
   - Clear old sessions
   - Force password reset for all users

4. **Notification**
   - Document incident details
   - Notify relevant stakeholders
   - Update security policies
   - Share learnings with team

### Brute Force Attack

1. **Detection**
   - Monitor for multiple failed login attempts
   - Alert on >5 failures in 5 minutes

2. **Response**
   - Implement temporary IP blocking
   - Increase monitoring frequency
   - Consider CAPTCHA addition

3. **Prevention**
   - Add rate limiting
   - Implement account lockout
   - Require 2FA for admin access

---

## Dependencies & Vulnerabilities

### Security-Related Dependencies

- **Flask 2.3.3**: Web framework with security features
- **werkzeug 2.3.x**: Password hashing, secure session handling
- **Flask-CORS 4.0.0**: CORS policy enforcement
- **Gunicorn 21.2.0**: Production WSGI server

### Dependency Updates

Keep dependencies current to patch vulnerabilities:

```bash
# Check for outdated packages
pip list --outdated

# Update all packages
pip install --upgrade -r requirements.txt

# Check for known vulnerabilities
pip install safety
safety check
```

### Known Vulnerabilities

- Check [CVE Database](https://cve.mitre.org/) for any installed package versions
- Monitor [GitHub Security Alerts](https://github.com/settings/security) for your repo
- Subscribe to [Flask Security Updates](https://flask.palletsprojects.com/en/2.3.x/security/)

---

## Security Best Practices

### Development

- Never hardcode secrets (use environment variables)
- Always validate user input
- Use parameterized queries (prevents SQL injection)
- Sanitize output (prevents XSS)
- Log security events
- Use HTTPS even in development

### Deployment

- Use strong, unique passwords
- Rotate secrets regularly
- Monitor access logs
- Keep systems updated
- Use firewalls and network segmentation
- Implement intrusion detection
- Regular security audits

### Operations

- Monitor for suspicious activity
- Review access logs regularly
- Keep incident response plan updated
- Test backup and recovery procedures
- Maintain security documentation
- Train team on security practices
- Conduct security awareness training

---

## References

### Security Frameworks
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/cis-controls/)

### Flask Security
- [Flask Security Guide](https://flask.palletsprojects.com/en/2.3.x/security/)
- [Werkzeug Security](https://werkzeug.palletsprojects.com/en/2.3.x/security/)
- [Flask-Login Documentation](https://flask-login.readthedocs.io/)

### Web Security
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [Mozilla HTTP Header Guide](https://infosec.mozilla.org/guidelines/web_security)
- [SANS Secure Coding](https://www.sans.org/reading-room/whitepapers)

---

## Contact & Support

For security issues:

1. **Do NOT** open public GitHub issues for security vulnerabilities
2. Email security concerns to your security team
3. Follow your organization's vulnerability disclosure policy
4. Reference this document when reporting security issues

---

**Last Updated**: 2026-06-05  
**Security Level**: Production Ready  
**Maintained By**: Security Team
