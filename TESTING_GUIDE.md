# Qute-Mail Testing & Configuration Guide

## 🚀 Quick Start

Your Qute-Mail service is successfully deployed and running! Here's how to test and configure it.

## 📊 Service Status

✅ **Docker Services Running:**
- Django Web App: `http://localhost:8000`
- PostgreSQL Database: `localhost:5433`
- Redis Cache: `localhost:6380`
- MailHog SMTP Testing: `localhost:1025` (SMTP), `localhost:8025` (Web UI)
- Celery Workers: Background task processing

✅ **API Authentication:** Configured with Token Authentication

## 🔧 Access Points

### Django Admin Interface
- **URL:** http://localhost:8000/admin/
- **Username:** Your superuser credentials
- **Features:** Manage domains, email accounts, view emails

### REST API
- **Base URL:** http://localhost:8000/api/
- **Authentication:** Token-based (Header: `Authorization: Token YOUR_TOKEN`)
- **Endpoints:**
  - `/api/domains/` - Domain management
  - `/api/accounts/` - Email account management
  - `/api/emails/` - Email messages

### MailHog Web Interface
- **URL:** http://localhost:8025
- **Purpose:** View captured emails, test SMTP functionality
- **Features:** Email inbox, search, message details

## 🧪 Testing Examples

### 1. API Testing with PowerShell

```powershell
# Set your API token (replace with actual token)
$token = "d0f25a0a19ba0901b32e8dc0c3f4c03523b0d2b1"
$headers = @{"Authorization" = "Token $token"}

# List domains
Invoke-WebRequest -Uri "http://localhost:8000/api/domains/" -Headers $headers -UseBasicParsing

# List email accounts
Invoke-WebRequest -Uri "http://localhost:8000/api/accounts/" -Headers $headers -UseBasicParsing

# Create new email account
$createHeaders = @{"Authorization" = "Token $token"; "Content-Type" = "application/json"}
$body = '{"email_address": "newuser@localhost", "domain": 1, "password": "password123", "is_active": true, "quota_mb": 1000}'
Invoke-WebRequest -Uri "http://localhost:8000/api/accounts/" -Method POST -Headers $createHeaders -Body $body -UseBasicParsing
```

### 2. Email Testing

```bash
# Test email service functionality
docker-compose exec web python manage.py test_email_service

# Create test data
docker-compose exec web python manage.py create_test_data

# Generate new API token
docker-compose exec web python manage.py create_api_token
```

## 📧 Current Test Data

Your service includes:
- **Domain:** localhost (verified)
- **Email Accounts:**
  - admin@localhost
  - user@localhost  
  - support@localhost
  - test@localhost (newly created)

## 🔑 API Token

Current API Token: `d0f25a0a19ba0901b32e8dc0c3f4c03523b0d2b1`

**Usage:**
```
Authorization: Token d0f25a0a19ba0901b32e8dc0c3f4c03523b0d2b1
```

## 🐛 Known Issues & Status

### ✅ Working Components
- Django application startup
- Database connectivity
- API authentication
- SMTP connection to MailHog
- Domain and account management via API
- Admin interface access

### ⚠️ Minor Issues
- **MailHog Storage:** Permission issue with storing emails to disk, but emails are still processed and visible in web interface
- **Status:** Not critical - SMTP functionality works, only affects persistent storage

## 🔧 Configuration Tips

### Environment Variables
Your service uses the `.env` file for configuration:
```
DATABASE_URL=postgresql://qute_user:qute_password@db:5432/qute_mail
REDIS_URL=redis://redis:6379/0
EMAIL_HOST=smtp
EMAIL_PORT=1025
DEBUG=True
SECRET_KEY=your-secret-key
```

### Adding New Domains
1. Via Admin: http://localhost:8000/admin/email_core/domain/
2. Via API: POST to `/api/domains/`
3. Via Django shell:
```python
docker-compose exec web python manage.py shell
from email_core.models import Domain
Domain.objects.create(domain_name="yourdomain.com", is_verified=True)
```

### Creating Email Accounts
1. Via Admin: http://localhost:8000/admin/email_core/emailaccount/
2. Via API: POST to `/api/accounts/`
3. Via management command: `python manage.py create_test_data`

## 🔍 Monitoring & Logs

```bash
# View all service logs
docker-compose logs

# View specific service logs
docker-compose logs web      # Django app
docker-compose logs db       # PostgreSQL
docker-compose logs redis    # Redis
docker-compose logs smtp     # MailHog
docker-compose logs celery   # Celery worker

# Follow logs in real-time
docker-compose logs -f web
```

## 🚀 Next Steps

1. **Production Configuration:**
   - Set `DEBUG=False` in production
   - Use a proper SMTP server instead of MailHog
   - Configure proper domain DNS records
   - Add SSL/TLS certificates

2. **Email Features:**
   - Implement email receiving functionality
   - Add email filtering and rules
   - Configure SPF, DKIM, and DMARC records

3. **Security:**
   - Implement rate limiting
   - Add input validation
   - Configure proper authentication

## 📚 API Documentation

### Domains Endpoint
- **GET /api/domains/** - List all domains
- **POST /api/domains/** - Create new domain
- **GET /api/domains/{id}/** - Get domain details
- **PUT /api/domains/{id}/** - Update domain
- **DELETE /api/domains/{id}/** - Delete domain

### Email Accounts Endpoint
- **GET /api/accounts/** - List all email accounts
- **POST /api/accounts/** - Create new email account
- **GET /api/accounts/{id}/** - Get account details
- **PUT /api/accounts/{id}/** - Update account
- **DELETE /api/accounts/{id}/** - Delete account

### Required Fields for Account Creation:
```json
{
    "email_address": "user@domain.com",
    "domain": 1,
    "password": "secure_password",
    "is_active": true,
    "quota_mb": 1000
}
```

## 🛠️ Troubleshooting

### Common Issues:

1. **Container won't start:** Check port conflicts with `netstat -an | findstr :8000`
2. **Database connection errors:** Ensure PostgreSQL container is running
3. **API authentication fails:** Verify token format: `Authorization: Token YOUR_TOKEN`
4. **Email sending fails:** Check MailHog container and SMTP settings

### Service Health Check:
```bash
docker-compose ps  # Check all container status
curl http://localhost:8000/admin/  # Check web app
curl http://localhost:8025  # Check MailHog UI
```

Your email service is ready for testing and development! 🎉