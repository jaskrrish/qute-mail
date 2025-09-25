from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
import uuid
from datetime import datetime, timedelta
from django.utils import timezone


class AllowedDomain(models.Model):
    """Domains that users can register email accounts with"""
    domain_name = models.CharField(max_length=255, unique=True, help_text="Domain name (e.g., localhost, example.com)")
    display_name = models.CharField(max_length=255, help_text="Display name for the domain")
    description = models.TextField(blank=True, help_text="Optional description of the domain")
    is_active = models.BooleanField(default=True, help_text="Whether users can register with this domain")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.domain_name
    
    class Meta:
        ordering = ['domain_name']

class Domain(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='domains')
    domain_name = models.CharField(max_length=255, unique=True)
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=255)
    
    # DKIM Keys
    dkim_private_key = models.TextField()
    dkim_public_key = models.TextField()
    dkim_selector = models.CharField(max_length=63, default='default')
    
    # SPF Record
    spf_record = models.TextField()
    
    # DMARC Policy
    dmarc_policy = models.CharField(max_length=10, choices=[
        ('none', 'None'),
        ('quarantine', 'Quarantine'),
        ('reject', 'Reject')
    ], default='none')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def generate_dkim_keys(self):
        """Generate DKIM key pair for the domain"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self.dkim_private_key = private_pem.decode('utf-8')
        self.dkim_public_key = public_pem.decode('utf-8')
        
    def generate_spf_record(self, server_ip):
        """Generate SPF record for the domain"""
        self.spf_record = f"v=spf1 ip4:{server_ip} ~all"
        
    def get_dmarc_record(self):
        """Get DMARC record for DNS"""
        return f"v=DMARC1; p={self.dmarc_policy}; rua=mailto:dmarc@{self.domain_name}"
    
    class Meta:
        ordering = ['-created_at']

class EmailAccount(models.Model):
    # User information
    full_name = models.CharField(max_length=255, default="User", help_text="Full name of the user")
    email_address = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255, default="", help_text="Hashed password")
    
    # Domain association
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='email_accounts')
    allowed_domain = models.ForeignKey(AllowedDomain, on_delete=models.CASCADE, related_name='email_accounts', null=True, blank=True, help_text="Domain this account belongs to")
    
    # Account settings
    quota_mb = models.IntegerField(default=1000, help_text="Mailbox quota in MB")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True, help_text="Last successful login")
    
    def set_password(self, raw_password):
        """Set password with Django's built-in hashing"""
        self.password_hash = make_password(raw_password)
    
    def check_password(self, raw_password):
        """Check password against the stored hash"""
        return check_password(raw_password, self.password_hash)
    
    def get_domain_name(self):
        """Get the domain part of the email address"""
        return self.email_address.split('@')[1] if '@' in self.email_address else ''
    
    def __str__(self):
        return f"{self.full_name} <{self.email_address}>"
    
    class Meta:
        ordering = ['-created_at']

class Email(models.Model):
    email_account = models.ForeignKey(EmailAccount, on_delete=models.CASCADE, related_name='emails', null=True, blank=True)
    message_id = models.CharField(max_length=255, unique=True)
    from_address = models.EmailField()
    to_addresses = models.TextField()  # JSON field for multiple recipients
    subject = models.CharField(max_length=998)
    body_text = models.TextField(blank=True)
    body_html = models.TextField(blank=True)
    headers = models.JSONField(default=dict)
    size_bytes = models.IntegerField()
    
    # Security checks
    spf_pass = models.BooleanField(default=False)
    dkim_pass = models.BooleanField(default=False)
    dmarc_pass = models.BooleanField(default=False)
    spam_score = models.FloatField(default=0.0)
    
    is_read = models.BooleanField(default=False)
    is_sent = models.BooleanField(default=False)
    folder = models.CharField(max_length=50, default='INBOX')
    
    received_at = models.DateTimeField(auto_now_add=True)
    
    def get_to_addresses_list(self):
        """Return to_addresses as a list"""
        try:
            import json
            return json.loads(self.to_addresses) if self.to_addresses else []
        except json.JSONDecodeError:
            return [self.to_addresses] if self.to_addresses else []
    
    def set_to_addresses_list(self, addresses):
        """Set to_addresses from a list"""
        import json
        if isinstance(addresses, list):
            self.to_addresses = json.dumps(addresses)
        else:
            self.to_addresses = json.dumps([addresses])
    
    class Meta:
        ordering = ['-received_at']
        indexes = [
            models.Index(fields=['email_account', 'folder']),
            models.Index(fields=['message_id']),
        ]

class EmailAttachment(models.Model):
    email = models.ForeignKey(Email, on_delete=models.CASCADE, related_name='attachments')
    filename = models.CharField(max_length=255)
    content_type = models.CharField(max_length=100)
    size_bytes = models.IntegerField()
    file_data = models.BinaryField()
    
    class Meta:
        ordering = ['id']


# ========== QKD (Quantum Key Distribution) Models ==========

class QKDKeyManager(models.Model):
    """Key Manager configuration for ETSI GS QKD 014 compliance"""
    name = models.CharField(max_length=100, unique=True)
    base_url = models.URLField(help_text="Base URL for Key Manager REST API")
    api_version = models.CharField(max_length=10, default="v1")
    
    # Authentication
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)
    access_token = models.TextField(blank=True, null=True)
    token_expires_at = models.DateTimeField(blank=True, null=True)
    
    # Configuration
    default_key_size = models.IntegerField(default=256, help_text="Default key size in bits")
    max_key_lifetime = models.IntegerField(default=3600, help_text="Maximum key lifetime in seconds")
    is_simulated = models.BooleanField(default=True, help_text="Whether this is a simulated KM for testing")
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"KM-{self.name} ({'Simulated' if self.is_simulated else 'Real'})"


class QKDKey(models.Model):
    """Quantum keys retrieved from Key Manager"""
    STATUS_CHOICES = [
        ('available', 'Available'),
        ('reserved', 'Reserved'),
        ('consumed', 'Consumed'),
        ('expired', 'Expired'),
        ('error', 'Error'),
    ]
    
    key_manager = models.ForeignKey(QKDKeyManager, on_delete=models.CASCADE, related_name='keys')
    key_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    
    # ETSI QKD 014 fields
    ksid = models.CharField(max_length=255, help_text="Key Stream ID")
    key_data = models.BinaryField(help_text="Encrypted quantum key material")
    key_size_bits = models.IntegerField()
    
    # Key lifecycle
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='available')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(blank=True, null=True)
    
    # Usage tracking
    sender_email = models.EmailField(blank=True, null=True)
    recipient_email = models.EmailField(blank=True, null=True)
    usage_count = models.IntegerField(default=0)
    max_usage = models.IntegerField(default=1, help_text="Maximum number of times this key can be used")
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ksid', 'status']),
            models.Index(fields=['sender_email', 'recipient_email']),
            models.Index(fields=['expires_at']),
        ]
    
    def is_valid(self):
        """Check if key is still valid for use"""
        return (
            self.status == 'available' and 
            self.expires_at > timezone.now() and
            self.usage_count < self.max_usage
        )
    
    def consume(self):
        """Mark key as consumed"""
        if self.is_valid():
            self.usage_count += 1
            if self.usage_count >= self.max_usage:
                self.status = 'consumed'
                self.consumed_at = timezone.now()
            self.save()
            return True
        return False


class QKDSession(models.Model):
    """QKD communication session between two parties"""
    SESSION_STATUS = [
        ('initializing', 'Initializing'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('expired', 'Expired'),
        ('error', 'Error'),
    ]
    
    session_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    sender_email = models.EmailField()
    recipient_email = models.EmailField()
    
    # Key management
    key_manager = models.ForeignKey(QKDKeyManager, on_delete=models.CASCADE)
    shared_keys = models.ManyToManyField(QKDKey, blank=True)
    
    # Session lifecycle
    status = models.CharField(max_length=20, choices=SESSION_STATUS, default='initializing')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    completed_at = models.DateTimeField(blank=True, null=True)
    
    # Configuration
    encryption_algorithm = models.CharField(max_length=50, default='AES-256-GCM')
    key_derivation_rounds = models.IntegerField(default=10000)
    
    class Meta:
        ordering = ['-created_at']
        unique_together = ['sender_email', 'recipient_email', 'status']
    
    def is_active(self):
        """Check if session is active"""
        return (
            self.status == 'active' and 
            self.expires_at > timezone.now()
        )
    
    def get_available_key(self):
        """Get an available quantum key for encryption"""
        return self.shared_keys.filter(
            status='available',
            expires_at__gt=timezone.now()
        ).first()


class QuantumEncryptedEmail(models.Model):
    """Extension of Email model for quantum-encrypted emails"""
    email = models.OneToOneField(Email, on_delete=models.CASCADE, related_name='quantum_data')
    qkd_session = models.ForeignKey(QKDSession, on_delete=models.CASCADE, related_name='encrypted_emails')
    
    # Encryption metadata
    encryption_key = models.ForeignKey(QKDKey, on_delete=models.SET_NULL, null=True, blank=True)
    encryption_algorithm = models.CharField(max_length=50, default='AES-256-GCM')
    key_derivation_salt = models.BinaryField(max_length=32)
    initialization_vector = models.BinaryField(max_length=16)
    
    # Encrypted content
    encrypted_subject = models.BinaryField(blank=True, null=True)
    encrypted_body_text = models.BinaryField(blank=True, null=True)
    encrypted_body_html = models.BinaryField(blank=True, null=True)
    
    # Quantum security indicators
    quantum_security_level = models.IntegerField(default=256, help_text="Security level in bits")
    key_consumption_timestamp = models.DateTimeField()
    forward_secrecy_enabled = models.BooleanField(default=True)
    
    # Verification
    integrity_hash = models.CharField(max_length=64, help_text="SHA-256 hash for integrity verification")
    quantum_signature = models.BinaryField(blank=True, null=True, help_text="Quantum authentication signature")
    
    class Meta:
        ordering = ['-key_consumption_timestamp']
    
    def verify_integrity(self):
        """Verify the integrity of encrypted content"""
        import hashlib
        content_hash = hashlib.sha256(
            self.encrypted_subject + self.encrypted_body_text + self.encrypted_body_html
        ).hexdigest()
        return content_hash == self.integrity_hash


class ExternalEmailProvider(models.Model):
    """Configuration for external email providers (Gmail, Yahoo, etc.)"""
    PROVIDER_TYPES = [
        ('gmail', 'Gmail'),
        ('yahoo', 'Yahoo Mail'),
        ('outlook', 'Outlook.com'),
        ('custom_imap', 'Custom IMAP'),
        ('custom_smtp', 'Custom SMTP'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='external_email_providers')
    provider_type = models.CharField(max_length=20, choices=PROVIDER_TYPES)
    email_address = models.EmailField()
    
    # IMAP Configuration
    imap_server = models.CharField(max_length=255)
    imap_port = models.IntegerField()
    imap_use_ssl = models.BooleanField(default=True)
    
    # SMTP Configuration  
    smtp_server = models.CharField(max_length=255)
    smtp_port = models.IntegerField()
    smtp_use_ssl = models.BooleanField(default=True)
    smtp_use_tls = models.BooleanField(default=False)
    
    # Authentication
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)  # Should be encrypted
    oauth2_token = models.TextField(blank=True, null=True)
    oauth2_refresh_token = models.TextField(blank=True, null=True)
    oauth2_expires_at = models.DateTimeField(blank=True, null=True)
    
    # QKD Integration
    qkd_enabled = models.BooleanField(default=True, help_text="Enable quantum encryption for this provider")
    preferred_key_manager = models.ForeignKey(QKDKeyManager, on_delete=models.SET_NULL, null=True, blank=True)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        unique_together = ['user', 'email_address']
    
    def __str__(self):
        return f"{self.email_address} ({self.get_provider_type_display()})"


class RealQuantumEmail(models.Model):
    """Real quantum encrypted email using QKD system"""
    STATUS_CHOICES = [
        ('encrypted', 'Encrypted'),
        ('sent', 'Sent'),
        ('delivered', 'Delivered'), 
        ('decrypted', 'Decrypted'),
        ('error', 'Error')
    ]
    
    # Unique identifiers
    email_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    sender_email = models.EmailField()
    recipient_email = models.EmailField()
    
    # Encrypted content (stored as JSON strings)
    encrypted_subject = models.TextField(help_text="JSON string containing encrypted subject")
    encrypted_body_text = models.TextField(help_text="JSON string containing encrypted body text")
    encrypted_body_html = models.TextField(blank=True, null=True, help_text="JSON string containing encrypted HTML body")
    
    # Quantum metadata
    encryption_algorithm = models.CharField(max_length=50, default='AES-256-GCM')
    quantum_key_id = models.CharField(max_length=255, help_text="ID of quantum key used")
    quantum_security_level = models.FloatField(default=99.9, help_text="Quantum security level")
    quantum_envelope = models.TextField(help_text="JSON string containing quantum envelope data")
    
    # Status and lifecycle
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='encrypted')
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(blank=True, null=True)
    decrypted_at = models.DateTimeField(blank=True, null=True)
    
    # Relationships
    sender_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_quantum_emails')
    key_manager = models.ForeignKey(QKDKeyManager, on_delete=models.CASCADE, related_name='quantum_emails')
    regular_email = models.ForeignKey(Email, on_delete=models.SET_NULL, null=True, blank=True, related_name='real_quantum_data')
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Quantum Email {self.email_id} ({self.sender_email} → {self.recipient_email})"