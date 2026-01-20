# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please email the maintainers directly. Do NOT create a public GitHub issue.

## Security Best Practices

### 1. Environment Variables

**CRITICAL**: Never commit `.env` files or expose credentials in code.

Required environment variables:
- `SECRET_KEY`: Generate with `python -c "import secrets; print(secrets.token_hex(32))"`
- `POSTGRES_PASSWORD`: Use a strong, unique password
- `DATABASE_URL`: Keep database credentials secure

### 2. Authentication

Authentication is **optional** by default for development convenience.

To enable authentication in production:
```bash
REQUIRE_AUTH=true
```

#### Default Admin User

On first startup, a default admin user is created:
- **Username**: `admin`
- **Password**: `changeme123`

**⚠️ CHANGE THIS IMMEDIATELY IN PRODUCTION!**

#### API Authentication Methods

1. **JWT Tokens** (recommended for web apps):
   ```bash
   # Login to get token
   curl -X POST http://localhost:8000/auth/login \
     -d "username=admin&password=yourpassword"
   
   # Use token in requests
   curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/api/search
   ```

2. **API Keys** (recommended for programmatic access):
   ```bash
   # Create API key (requires authentication)
   curl -X POST http://localhost:8000/auth/api-keys \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"key_name": "my-app", "expires_days": 90}'
   
   # Use API key in requests
   curl -H "Authorization: ApiKey YOUR_API_KEY" \
     http://localhost:8000/api/search
   ```

### 3. CORS Configuration

Configure allowed origins in `.env`:
```bash
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

Never use `*` (allow all) in production.

### 4. Rate Limiting

Default: 60 requests per minute per IP.

Adjust in `.env`:
```bash
RATE_LIMIT_PER_MINUTE=100
```

### 5. HTTPS/TLS

**Always use HTTPS in production.**

For Docker deployments, use a reverse proxy (nginx, Traefik, Caddy) with TLS certificates.

### 6. Database Security

- Use strong passwords
- Restrict database access to application servers only
- Enable SSL/TLS for database connections in production
- Regular backups with encryption

### 7. Input Validation

All user inputs are sanitized to prevent:
- SQL injection
- XSS attacks
- Command injection

### 8. Secrets Management

**DO NOT**:
- Commit `.env` files
- Hardcode credentials
- Share API keys publicly
- Use default passwords in production

**DO**:
- Use environment variables
- Rotate secrets regularly
- Use secret management tools (AWS Secrets Manager, HashiCorp Vault, etc.)
- Enable 2FA where possible

### 9. Docker Security

- Run containers as non-root users
- Use official base images
- Keep images updated
- Scan for vulnerabilities regularly
- Use Docker secrets for sensitive data

### 10. Monitoring & Logging

- Monitor failed authentication attempts
- Log security events
- Set up alerts for suspicious activity
- Regular security audits

## Production Deployment Checklist

- [ ] Change default admin password
- [ ] Generate strong `SECRET_KEY`
- [ ] Set strong `POSTGRES_PASSWORD`
- [ ] Enable authentication (`REQUIRE_AUTH=true`)
- [ ] Configure CORS with specific origins
- [ ] Enable HTTPS/TLS
- [ ] Set up firewall rules
- [ ] Configure rate limiting
- [ ] Enable database SSL
- [ ] Set up monitoring and alerts
- [ ] Regular backups
- [ ] Update dependencies regularly
- [ ] Review and rotate API keys
- [ ] Implement IP whitelisting if needed

## Security Headers

The application includes security headers:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-XSS-Protection: 1; mode=block`

## Dependencies

Keep dependencies updated:
```bash
# Backend
cd backend
pip install --upgrade -r requirements.txt

# Frontend
cd frontend
npm audit fix
npm update
```

## Contact

For security concerns, contact the repository maintainers.

