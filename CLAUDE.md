# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Qute Mail** is a professional, enterprise-grade email service built with Django. It provides secure email hosting with SMTP/IMAP services, domain management, quantum key distribution (QKD) integration, and advanced email security features (DKIM, SPF, DMARC).

**Key Technologies:**
- **Backend:** Django 4.2 + Django REST Framework 3.14
- **Email:** aiosmtpd (async SMTP), dkimpy (DKIM), dnspython (DNS validation)
- **Database:** PostgreSQL (production), SQLite (dev)
- **Cache/Queue:** Redis, Celery
- **QKD:** ETSI GS QKD 014 client, cryptography, pycryptodome
- **Frontend:** Bootstrap 5 + Vanilla JavaScript
- **Testing:** pytest, pytest-django, pytest-asyncio
- **Deployment:** Docker Compose, Gunicorn/Uvicorn

---

## Core Architecture

### Data Models (email_core/models.py)

**Primary Models:**
- `AllowedDomain` - Whitelisted registration domains
- `Domain` - User-owned domains with DKIM keys, SPF, DMARC configuration
- `EmailAccount` - User email accounts with bcrypt-hashed passwords
- `Email` - Stored email messages with security validation flags (spf_pass, dkim_pass, dmarc_pass)
- `EmailAttachment` - Attachments with binary file storage

**QKD Models:**
- `QKDKeyManager` - Connection to external ETSI QKD 014 Key Manager services
- `QKDKey` - Individual quantum keys with lifecycle tracking (creation, expiry, usage)
- `QKDSession` - QKD communication sessions between parties
- `QuantumEncryptedEmail` - Extended Email model storing quantum encryption metadata
- `RealQuantumEmail` - Real quantum-encrypted emails using actual QKD keys

**Other Models:**
- `ExternalEmailProvider` - Gmail, Yahoo, Outlook OAuth2 integrations

**Model Relationships:**
```
User → Domain (1:N)
Domain → EmailAccount (1:N)
EmailAccount → Email (1:N)
Email → EmailAttachment (1:N)
QKDKeyManager → QKDKey (1:N)
QKDKeyManager → QKDSession (1:N)
QKDSession → QKDKey (M:M via SessionKey join table)
```

### REST API Architecture

**ViewSets & Endpoints:**
- `DomainViewSet` (`/api/domains/`) - CRUD, `verify/`, `dns_check/`
- `EmailAccountViewSet` (`/api/accounts/`) - User email accounts
- `EmailViewSet` (`/api/emails/`) - Email list, retrieve, mark_read
- `QKDKeyManagerViewSet` (`/api/qkd/key-managers/`) - KM config, `test_connection/`
- `QKDSessionViewSet` (`/api/qkd/sessions/`) - Session management
- `ExternalEmailProviderViewSet` (`/api/qkd/providers/`) - Third-party integrations
- `QuantumEmailAPIView` (`/api/quantum-emails/`) - `send/`, `decrypt/`

**Web Client Routes:**
- `/client/login/` - User authentication
- `/client/register/` - Account creation
- `/client/` - Multi-user inbox interface
- `/client/send/` - Email composition
- `/api/qkd/status/` - Public QKD status endpoint

### Business Logic Organization

**SMTP Processing (email_core/smtp/):**
- `smtp_server.py` - Async SMTP server using aiosmtpd, AUTH support
- `smtp_handler.py` - Email storage, attachment handling
- `security.py` - SPF/DKIM/DMARC validation, DKIM signing

**QKD Orchestration (email_core/qkd/):**
- `key_manager.py` - ETSI QKD 014 REST client, OAuth2 authentication
- `crypto.py` - AES-256-GCM encryption/decryption using QKD keys
- `service.py` - High-level QKD operations (session creation, encryption, decryption)
- `external_providers.py` - Gmail/Yahoo/Outlook OAuth2 integration
- `real_crypto.py` - Real quantum cryptographic operations
- `views.py` - QKD API endpoints

---

## Common Development Commands

### Setup & Configuration

```bash
# Install dependencies
pip install -r requirements.txt

# Setup environment (copy template)
cp .env.example .env

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic --noinput
```

### Running the Application

```bash
# Development server (default: http://localhost:8000)
python manage.py runserver

# With Docker Compose (all services)
docker-compose up --build

# Specific service only
docker-compose up web
docker-compose up smtp  # MailHog on http://localhost:8025
docker-compose up redis
```

### Testing

```bash
# Run all tests
pytest

# Run specific test file
pytest email_core/tests.py

# Run with coverage report
pytest --cov=email_core --cov-report=html

# Run a single test
pytest email_core/tests.py::TestEmailSending::test_send_email

# Async test execution
pytest -n auto  # requires pytest-xdist
```

### Management Commands

```bash
# Email/SMTP testing
python manage.py test_email_service

# QKD system setup
python manage.py setup_qkd_system
python manage.py generate_quantum_keys
python manage.py verify_qkd_system
python manage.py check_quantum_keys

# Authentication
python manage.py create_api_token <username>

# Test data
python manage.py create_test_data
```

### Code Quality

```bash
# Format code
black .

# Lint
flake8 .

# Type checking
mypy .
```

### Database

```bash
# Create migrations after model changes
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Show migration status
python manage.py showmigrations
```

---

## Project Structure

```
qute-mail/
├── email_service/           # Django project settings
│   ├── settings.py         # Core Django config, DB, cache, email setup
│   ├── urls.py             # Main URL routing
│   ├── wsgi.py
│   └── asgi.py
├── email_core/             # Main Django app
│   ├── models.py           # 9 database models (Email, Domain, QKD, etc.)
│   ├── views.py            # ViewSets & REST API views (~800 lines)
│   ├── serializers.py      # DRF serializers for API responses
│   ├── urls.py
│   ├── admin.py
│   ├── apps.py
│   ├── smtp/
│   │   ├── smtp_server.py  # Async SMTP server (aiosmtpd-based)
│   │   ├── smtp_handler.py # Email processing & storage
│   │   └── security.py     # SPF, DKIM, DMARC validation & signing
│   ├── qkd/
│   │   ├── key_manager.py  # ETSI GS QKD 014 REST client
│   │   ├── crypto.py       # Quantum encryption/decryption
│   │   ├── service.py      # QKD orchestration service
│   │   ├── views.py        # QKD API endpoints
│   │   ├── external_providers.py  # OAuth2 integrations
│   │   └── real_crypto.py  # Real quantum crypto ops
│   ├── management/commands/
│   │   ├── test_email_service.py
│   │   ├── setup_qkd_system.py
│   │   ├── create_api_token.py
│   │   └── ... (6 more)
│   ├── migrations/         # Database migrations
│   ├── templates/
│   │   └── email_core/
│   │       ├── base.html   # Base template with nav & Bootstrap 5
│   │       ├── login.html  # Django auth form
│   │       ├── register.html
│   │       └── inbox.html  # Multi-user email client, QKD status panel
│   ├── static/
│   │   ├── js/email-client.js  # Keyboard shortcuts, fetch API, auto-refresh
│   │   └── css/
│   └── tests.py
├── manage.py               # Django management script
├── requirements.txt        # 78 Python dependencies
├── requirements-docker.txt
├── docker-compose.yml      # 6 services: web, db, redis, smtp, celery, nginx
├── Dockerfile              # Python 3.11, non-root user, health check
├── .env.example            # Template for environment variables
├── README.md               # Comprehensive user documentation
├── TESTING_GUIDE.md        # Service access & API examples
├── MULTI_USER_TESTING.md   # Test scenarios & accounts
└── CLAUDE.md              # This file
```

---

## Key Environment Variables

Reference `.env.example` for complete list. Critical ones:

```bash
# Django
SECRET_KEY=<change-in-production>
DEBUG=False  # Always False in production
ALLOWED_HOSTS=example.com

# Database (PostgreSQL in production)
DB_NAME=qute_mail
DB_USER=postgres
DB_PASSWORD=<secure>
DB_HOST=db  # 'localhost' for manual, 'db' for Docker
DB_PORT=5432

# Email Service
SERVER_HOSTNAME=mail.yourdomain.com
SERVER_IP=your.server.ip

# Redis (Celery & session cache)
REDIS_URL=redis://redis:6379/0

# SMTP Ports
SMTP_PORT=25
SMTP_SSL_PORT=465
SMTP_TLS_PORT=587

# Rate Limiting
SMTP_MAX_CONNECTIONS_PER_IP=10
SMTP_RATE_LIMIT_WINDOW=3600      # seconds
SMTP_RATE_LIMIT_MAX_EMAILS=100   # per window
```

---

## API Authentication & Examples

### Token Authentication

All API requests require token authentication:

```bash
# Get token (API endpoint)
curl -X POST http://localhost:8000/api-token-auth/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# Use token in requests
curl -H "Authorization: Token <your-token>" \
  http://localhost:8000/api/emails/
```

### Common API Operations

```bash
# List domains
curl -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/domains/

# Verify domain (triggers DNS check)
curl -X POST -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/domains/1/verify/

# Send email via API
curl -X POST -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to":["test@example.com"],"subject":"Test","body":"Body"}' \
  http://localhost:8000/api/emails/

# QKD Key Manager connection
curl -X POST -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"KM1","url":"http://km:8000","client_id":"...","client_secret":"..."}' \
  http://localhost:8000/api/qkd/key-managers/

# Test KM connection
curl -X POST -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/qkd/key-managers/1/test_connection/
```

---

## Frontend Architecture

### Templates (Django Template Language + Bootstrap 5)

- **base.html** - Navigation bar, static file includes, block structure
- **login.html** - User authentication form
- **register.html** - Account creation
- **inbox.html** - Main email client interface
  - QKD status panel (security level, available keys)
  - Folder navigation (Inbox, Sent, Draft, Spam)
  - Email list with sender, subject, unread indicator
  - Single email view with quoted text
  - Compose modal for new emails
  - Quantum Email button for QKD-encrypted messages

### JavaScript (email-client.js)

- **Keyboard Shortcuts:**
  - `c` - Compose new email
  - `r` - Refresh inbox
  - `Ctrl+Enter` - Send email from compose modal

- **Features:**
  - Auto-refresh inbox every 30 seconds (fetch API)
  - Modal-based composition
  - Typing detection for shortcuts
  - Form submission handling
  - Dynamic email list updates

---

## Important Implementation Details

### Email Sending Flow

```
User submits form
  ↓
EmailViewSet.create() (views.py)
  ↓
Validate serializer & get email account
  ↓
DKIMSigner.sign_email() (security.py) - Add DKIM signature
  ↓
Send via SMTP (smtplib or aiosmtpd client)
  ↓
Store Email model in database
  ↓
Return HTTP response
```

### Email Receiving Flow

```
SMTP connection on port 25/465/587
  ↓
AuthenticatedSMTPServer.authenticate() - Validate credentials
  ↓
EmailHandler.handle_DATA() - Process message
  ↓
SecurityChecker - SPF/DKIM/DMARC validation
  ↓
Email.create() - Store in database with security flags
  ↓
EmailAttachment.create() - Extract & store attachments
```

### Quantum Email (QKD) Flow

```
User initiates quantum send
  ↓
QuantumEmailAPIView.send() (qkd/views.py)
  ↓
QKDService.create_qkd_session() - Session with recipient's KM
  ↓
ETSIQKDClient.get_key() - Retrieve quantum key from Key Manager
  ↓
QuantumCrypto.encrypt_email() - AES-256-GCM with QKD key
  ↓
RealQuantumEmail.create() - Store metadata
  ↓
ExternalEmailClient.send() - Send via external provider
  ↓
Return encrypted payload to user
```

### QKD Key Lifecycle

```
Key Generation (generate_quantum_keys.py)
  ↓
QKDKey created with status=available
  ↓
RealQuantumEmail uses key (status=used)
  ↓
Expiry check (check_quantum_keys.py)
  ↓
Status transitions to expired/revoked
```

### SMTP Security Validation

**SPF Check (security.py:check_spf()):**
- Query DNS TXT record for `v=spf1` rules
- Validate sender IP against SPF record
- Set `Email.spf_pass` flag

**DKIM Check (security.py:check_dkim()):**
- Extract DKIM signature from email headers
- Fetch public key from DNS (`default._domainkey`)
- Verify signature cryptographically
- Set `Email.dkim_pass` flag

**DMARC Check (security.py:check_dmarc()):**
- Query DNS `_dmarc` TXT record
- Enforce policy (none, quarantine, reject)
- Set `Email.dmarc_pass` flag

**DKIM Signing (security.py:DKIMSigner):**
- Uses domain's DKIM private key
- Signs outgoing emails automatically
- Adds `DKIM-Signature` header

---

## Database Schema Notes

### Key Indexes
- `Email.account` - For account inbox queries
- `Domain.user` - For user domain queries
- `QKDKey.key_manager` - For key lookup
- `QKDSession.created_at` - For session ordering
- Multiple composite indexes on frequently-filtered fields

### Default Behaviors
- `Email.body` uses TextField for unlimited size
- `EmailAttachment.file` stores raw binary
- Passwords hashed with Django's default (PBKDF2 or bcrypt via integration)
- Timestamps auto-set (`auto_now_add`, `auto_now`)

---

## Testing Strategy

### Test File Location
`email_core/tests.py` + root-level integration tests

### Test Coverage Areas
- Email CRUD operations
- SMTP server authentication & message processing
- QKD key management & encryption/decryption
- Domain verification & DNS checking
- External provider OAuth2 flows
- API endpoint authorization
- Multi-user inbox isolation

### Running Tests
```bash
pytest                          # All tests
pytest -v                      # Verbose
pytest --cov=email_core        # Coverage report
pytest -k "test_send"          # Filter by name
pytest email_core/tests.py::TestClass::test_method  # Single test
```

### Async Test Support
- `pytest-asyncio` for async function testing
- Use `@pytest.mark.asyncio` decorator
- Example: Testing `EmailHandler` async message processing

---

## Docker Compose Services

**Services defined in docker-compose.yml:**

- **web** - Django app on port 8000 (gunicorn)
- **db** - PostgreSQL 15 on port 5433 (internal 5432)
- **redis** - Redis on port 6380 (internal 6379)
- **smtp** - MailHog SMTP on port 1025, UI on 8025
- **celery** - Async worker (can scale with `--scale celery=3`)
- **celery-beat** - Scheduled tasks
- **nginx** - Reverse proxy (optional, production profile)

**Quick commands:**
```bash
docker-compose up --build              # Start all services
docker-compose down                    # Stop all
docker-compose exec web python manage.py migrate  # Run migrations
docker-compose logs -f web             # View Django logs
docker-compose logs -f smtp            # View MailHog logs
```

---

## Common Debugging Scenarios

### Email Not Sending
1. Check SMTP credentials in `.env`
2. Verify EmailAccount exists in database
3. Check `python manage.py runserver` logs for exceptions
4. Inspect MailHog UI (`http://localhost:8025`) if using Docker
5. Verify domain configuration (DKIM key, SPF, DMARC)

### QKD Integration Issues
1. Verify Key Manager is running and reachable (`test_connection/` endpoint)
2. Check OAuth2 credentials in QKDKeyManager model
3. Review quantum key availability (`check_quantum_keys.py`)
4. Check Redis connectivity for session caching
5. Inspect Celery logs for async encryption failures

### API Token Issues
1. Generate token: `python manage.py create_api_token <username>`
2. Include in request: `Authorization: Token <token>`
3. Check user permissions in Django Admin

### Database Connection
1. Verify DB_* environment variables
2. Ensure PostgreSQL service is running (Docker: `docker-compose logs db`)
3. Run migrations: `python manage.py migrate`
4. Check firewall rules on port 5432 (local) or 5433 (Docker)

---

## Performance & Optimization Tips

1. **Email Queries** - Add `select_related('account')` to Email querysets
2. **Pagination** - Use DRF pagination on email list endpoints
3. **Caching** - Store domain DNS records in Redis
4. **Async Tasks** - Use Celery for DKIM signing, external API calls
5. **Database Indexes** - Check `models.py` for Meta.indexes
6. **Connection Pooling** - Configured in docker-compose (PostgreSQL)

---

## External Dependencies & Integrations

### Email Provider OAuth2
- **Gmail API** - `google-auth-oauthlib` (external_providers.py)
- **Yahoo Mail** - IMAP/SMTP via OAuth2 tokens
- **Outlook** - Microsoft Graph API

### Key Manager (ETSI GS QKD 014)
- Communicates via REST API (requests library)
- OAuth2 authentication
- Key retrieval for encryption/decryption

### Email Validation
- `dnspython` - DNS lookups (SPF, DKIM, DMARC)
- `dkimpy` - DKIM operations
- `cryptography` - Signature verification

---

## Documentation Files

- **README.md** - Full user & installation guide, API reference
- **TESTING_GUIDE.md** - Service access points, API examples, known issues
- **MULTI_USER_TESTING.md** - Multi-user test scenarios, accounts, email flows
- **CLAUDE.md** - This file (Claude Code guidance)

