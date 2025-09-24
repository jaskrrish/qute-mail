from django.db import models
from django.contrib.auth.models import User
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

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
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='email_accounts')
    email_address = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    quota_mb = models.IntegerField(default=1000)  # Mailbox quota in MB
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']

class Email(models.Model):
    email_account = models.ForeignKey(EmailAccount, on_delete=models.CASCADE, related_name='emails')
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