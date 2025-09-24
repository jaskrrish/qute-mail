# Qute Mail - Professional Email Service

A comprehensive, enterprise-grade email service built with Django and modern Python technologies. Qute Mail provides secure email hosting, SMTP/IMAP services, domain management, and advanced email security features including DKIM, SPF, and DMARC support.

## 🚀 Features

### Core Email Features
- **Multi-domain Support**: Manage multiple email domains from a single installation
- **Email Account Management**: Create and manage email accounts with quotas
- **SMTP/IMAP Services**: Full-featured email server with authentication
- **Email Storage**: Secure email storage with folder organization
- **Attachment Support**: Handle email attachments with size limits

### Security & Authentication
- **DKIM Signing**: Automatic DKIM signature generation and verification
- **SPF Records**: SPF record generation and validation
- **DMARC Support**: DMARC policy enforcement and reporting
- **Rate Limiting**: IP-based rate limiting and connection throttling
- **Authentication**: Secure SMTP/IMAP authentication
- **Spam Detection**: Built-in spam scoring and filtering

### Domain Management
- **DNS Verification**: Automatic domain ownership verification
- **DNS Record Generation**: Auto-generate required MX, TXT, DKIM records
- **SSL/TLS Support**: Encrypted email transmission
- **Domain Security**: Per-domain security policies

### API & Integration
- **REST API**: Complete RESTful API for all operations
- **Django Admin**: Web-based administration interface
- **Bulk Operations**: Batch email operations and management
- **Webhooks**: Real-time email event notifications

## 🏗️ Architecture

```
qute-mail/
├── email_service/          # Main Django project
│   ├── __init__.py
│   ├── settings.py        # Core configuration
│   ├── urls.py           # URL routing
│   ├── wsgi.py           # WSGI configuration
│   └── asgi.py           # ASGI configuration
├── email_core/            # Core email application
│   ├── models.py         # Database models
│   ├── views.py          # API views and endpoints
│   ├── serializers.py    # REST framework serializers
│   ├── urls.py           # App URL patterns
│   ├── admin.py          # Django admin configuration
│   └── smtp/             # SMTP server implementation
│       ├── smtp_server.py    # SMTP server core
│       ├── smtp_handler.py   # Email processing
│       └── security.py      # Security & validation
├── requirements.txt       # Python dependencies
├── docker-compose.yml    # Docker orchestration
└── manage.py            # Django management script
```

## 📋 Prerequisites

- Python 3.9+
- PostgreSQL 12+
- Redis 6+
- Docker & Docker Compose (for containerized deployment)

## 🛠️ Installation

### Option 1: Docker Deployment (Recommended)

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd qute-mail
   ```

2. **Start the services**:
   ```bash
   docker-compose up --build
   ```

3. **Access the application**:
   - API: http://localhost:8000/api/
   - Admin: http://localhost:8000/admin/
   - MailHog UI: http://localhost:8025/

### Option 2: Manual Installation

1. **Clone and setup virtual environment**:
   ```bash
   git clone <repository-url>
   cd qute-mail
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Setup environment variables**:
   ```bash
   export SECRET_KEY="your-secret-key-here"
   export DEBUG=True
   export DB_NAME=qute_mail
   export DB_USER=postgres
   export DB_PASSWORD=password
   export DB_HOST=localhost
   export DB_PORT=5432
   export SERVER_HOSTNAME=mail.yourdomain.com
   export SERVER_IP=your.server.ip
   ```

4. **Database setup**:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   python manage.py createsuperuser
   ```

5. **Start the development server**:
   ```bash
   python manage.py runserver
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key | Required |
| `DEBUG` | Debug mode | `False` |
| `DB_NAME` | Database name | `email_service` |
| `DB_USER` | Database user | `postgres` |
| `DB_PASSWORD` | Database password | `password` |
| `DB_HOST` | Database host | `localhost` |
| `DB_PORT` | Database port | `5432` |
| `SERVER_HOSTNAME` | Email server hostname | `mail.yourdomain.com` |
| `SERVER_IP` | Server IP address | `0.0.0.0` |

### Email Service Configuration

The email service is configured via `EMAIL_SERVICE_CONFIG` in settings:

```python
EMAIL_SERVICE_CONFIG = {
    'SMTP_PORT': 25,           # Standard SMTP port
    'SMTP_SSL_PORT': 465,      # SMTP over SSL
    'SMTP_TLS_PORT': 587,      # SMTP with STARTTLS
    'IMAP_PORT': 143,          # Standard IMAP port
    'IMAP_SSL_PORT': 993,      # IMAP over SSL
    'SERVER_HOSTNAME': 'mail.yourdomain.com',
    'SERVER_IP': 'your.server.ip',
}
```

## 🔗 API Reference

### Authentication
All API endpoints require authentication. Use Django's built-in authentication or implement custom authentication.

### Domains

**List domains**
```http
GET /api/domains/
```

**Create domain**
```http
POST /api/domains/
Content-Type: application/json

{
    "domain_name": "example.com",
    "dmarc_policy": "none"
}
```

**Verify domain**
```http
POST /api/domains/{id}/verify/
```

**Check DNS records**
```http
GET /api/domains/{id}/dns_check/
```

### Email Accounts

**List email accounts**
```http
GET /api/accounts/
```

**Create email account**
```http
POST /api/accounts/
Content-Type: application/json

{
    "domain": 1,
    "email_address": "user@example.com",
    "password": "secure_password",
    "quota_mb": 1000
}
```

**Send email**
```http
POST /api/accounts/send_email/
Content-Type: application/json

{
    "from": "sender@example.com",
    "to": ["recipient@example.com"],
    "subject": "Test Email",
    "body": "Hello, World!"
}
```

### Emails

**List emails**
```http
GET /api/emails/
```

**Mark as read**
```http
POST /api/emails/{id}/mark_read/
```

## 📧 DNS Configuration

For each domain, you need to configure the following DNS records:

### MX Record
```
Type: MX
Host: @
Value: mail.yourdomain.com
Priority: 10
```

### SPF Record
```
Type: TXT
Host: @
Value: v=spf1 ip4:YOUR_SERVER_IP ~all
```

### DKIM Record
```
Type: TXT
Host: default._domainkey
Value: v=DKIM1; k=rsa; p=YOUR_DKIM_PUBLIC_KEY
```

### DMARC Record
```
Type: TXT
Host: _dmarc
Value: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com
```

## 🛡️ Security Features

### SMTP Security
- **Rate Limiting**: Configurable per-IP rate limits
- **IP Filtering**: Allow/block specific IP ranges
- **Authentication**: Secure SMTP-AUTH support
- **Connection Limits**: Maximum connections per IP

### Email Security
- **DKIM Signing**: All outgoing emails are DKIM signed
- **SPF Validation**: Incoming emails validated against SPF
- **DMARC Checking**: DMARC policy enforcement
- **Spam Filtering**: Configurable spam detection

### Data Security
- **Encrypted Storage**: Passwords stored with Django's hash algorithms
- **SSL/TLS**: All connections encrypted in production
- **Access Control**: User-based domain and account isolation

## 🔄 Development

### Running Tests
```bash
python manage.py test
```

### Code Quality
```bash
# Format code
black .

# Lint code
flake8 .

# Type checking
mypy .
```

### Database Migrations
```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate
```

## 📊 Monitoring & Logging

### Logging Configuration
Logs are structured using Django's logging framework:
- **Email Processing**: SMTP/IMAP operations
- **Security Events**: Authentication failures, rate limits
- **API Access**: Request/response logging
- **Error Tracking**: Exception monitoring

### Health Checks
- **Database**: Connection and query performance
- **Redis**: Cache availability
- **SMTP Server**: Port accessibility
- **Disk Space**: Storage usage monitoring

## 🚀 Production Deployment

### Prerequisites
- Domain with DNS control
- SSL certificates
- Firewall configuration (ports 25, 587, 993, 80, 443)

### Production Settings
1. **Set DEBUG=False**
2. **Configure ALLOWED_HOSTS**
3. **Setup SSL certificates**
4. **Configure reverse proxy (Nginx)**
5. **Setup monitoring (Sentry, etc.)**

### Docker Production
```bash
# Production build
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Scale services
docker-compose up --scale celery=3
```

## 📈 Performance Optimization

### Database
- **Indexes**: Optimized database indexes for email queries
- **Connection Pooling**: Database connection optimization
- **Query Optimization**: N+1 query prevention

### Caching
- **Redis Caching**: Email metadata and session caching
- **Template Caching**: Rendered template caching
- **API Response Caching**: Cacheable API responses

### Email Processing
- **Async Processing**: Celery-based background tasks
- **Bulk Operations**: Efficient batch processing
- **Queue Management**: Priority-based email queues

## 🐛 Troubleshooting

### Common Issues

**SMTP Connection Refused**
- Check firewall settings (port 25, 587)
- Verify DNS MX records
- Check server logs for authentication errors

**Domain Verification Failed**
- Ensure DNS records are properly configured
- Allow propagation time (up to 24 hours)
- Check DNS with external tools

**Email Not Delivered**
- Check DKIM/SPF/DMARC configuration
- Verify recipient domain policies
- Review email logs for delivery status

### Log Files
- Application logs: `/app/logs/django.log`
- SMTP logs: `/app/logs/smtp.log`
- Security logs: `/app/logs/security.log`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Run development server
python manage.py runserver
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Wiki](https://github.com/your-repo/qute-mail/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-repo/qute-mail/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/qute-mail/discussions)
- **Email**: support@qutemail.com

## 🙏 Acknowledgments

- Django REST Framework for API development
- aiosmtpd for SMTP server implementation
- PostgreSQL for reliable data storage
- Redis for caching and session management
- Docker for containerization

---

**Built with ❤️ by the Qute Mail Team**