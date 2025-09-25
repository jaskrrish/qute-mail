from rest_framework import serializers
from .models import (
    Domain, EmailAccount, Email, EmailAttachment,
    QKDKeyManager, QKDKey, QKDSession, QuantumEncryptedEmail, ExternalEmailProvider
)

class DomainSerializer(serializers.ModelSerializer):
    dns_records = serializers.SerializerMethodField()
    
    class Meta:
        model = Domain
        fields = ['id', 'domain_name', 'is_verified', 'verification_token', 
                 'dkim_selector', 'spf_record', 'dmarc_policy', 'dns_records',
                 'created_at', 'updated_at']
        read_only_fields = ['verification_token', 'dkim_private_key', 'dkim_public_key']
    
    def get_dns_records(self, obj):
        """Return required DNS records for domain setup"""
        from django.conf import settings
        server_ip = settings.EMAIL_SERVICE_CONFIG['SERVER_IP']
        
        return {
            'mx': {
                'type': 'MX',
                'host': '@',
                'value': settings.EMAIL_SERVICE_CONFIG['SERVER_HOSTNAME'],
                'priority': 10
            },
            'spf': {
                'type': 'TXT',
                'host': '@',
                'value': obj.spf_record or f"v=spf1 ip4:{server_ip} ~all"
            },
            'dkim': {
                'type': 'TXT',
                'host': f"{obj.dkim_selector}._domainkey",
                'value': self.format_dkim_record(obj.dkim_public_key)
            },
            'dmarc': {
                'type': 'TXT',
                'host': '_dmarc',
                'value': obj.get_dmarc_record()
            }
        }
    
    def format_dkim_record(self, public_key):
        """Format DKIM public key for DNS"""
        if not public_key:
            return ''
        # Remove PEM headers and format for DNS
        key_lines = public_key.split('\n')
        key_data = ''.join([line for line in key_lines if not line.startswith('-----')])
        return f"v=DKIM1; k=rsa; p={key_data}"

class EmailAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailAccount
        fields = ['id', 'domain', 'email_address', 'quota_mb', 
                 'is_active', 'created_at']
        read_only_fields = ['created_at']
    
    def create(self, validated_data):
        """Create email account with hashed password"""
        from django.contrib.auth.hashers import make_password
        password = self.context['request'].data.get('password')
        validated_data['password_hash'] = make_password(password)
        return super().create(validated_data)

class EmailSerializer(serializers.ModelSerializer):
    attachments = serializers.SerializerMethodField()
    
    class Meta:
        model = Email
        fields = ['id', 'message_id', 'from_address', 'to_addresses',
                 'subject', 'body_text', 'body_html', 'headers',
                 'size_bytes', 'spf_pass', 'dkim_pass', 'dmarc_pass',
                 'spam_score', 'is_read', 'folder', 'received_at', 'attachments']
    
    def get_attachments(self, obj):
        return [{
            'id': att.id,
            'filename': att.filename,
            'content_type': att.content_type,
            'size_bytes': att.size_bytes
        } for att in obj.attachments.all()]


# ========== QKD (Quantum Key Distribution) Serializers ==========

class QKDKeyManagerSerializer(serializers.ModelSerializer):
    key_statistics = serializers.SerializerMethodField()
    
    class Meta:
        model = QKDKeyManager
        fields = [
            'id', 'name', 'base_url', 'api_version', 'client_id',
            'default_key_size', 'max_key_lifetime', 'is_simulated',
            'is_active', 'created_at', 'updated_at', 'key_statistics'
        ]
        read_only_fields = ['access_token', 'token_expires_at', 'created_at', 'updated_at']
        extra_kwargs = {
            'client_secret': {'write_only': True}
        }
    
    def get_key_statistics(self, obj):
        """Get key usage statistics"""
        total_keys = obj.keys.count()
        available_keys = obj.keys.filter(status='available').count()
        consumed_keys = obj.keys.filter(status='consumed').count()
        
        return {
            'total_keys': total_keys,
            'available_keys': available_keys,
            'consumed_keys': consumed_keys,
            'utilization_rate': (consumed_keys / total_keys * 100) if total_keys > 0 else 0
        }


class QKDKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = QKDKey
        fields = [
            'id', 'key_id', 'ksid', 'key_size_bits', 'status',
            'created_at', 'expires_at', 'consumed_at', 'sender_email',
            'recipient_email', 'usage_count', 'max_usage'
        ]
        read_only_fields = ['key_data', 'created_at', 'consumed_at']  # Sensitive data


class QKDSessionSerializer(serializers.ModelSerializer):
    available_keys_count = serializers.SerializerMethodField()
    consumed_keys_count = serializers.SerializerMethodField()
    key_manager_name = serializers.CharField(source='key_manager.name', read_only=True)
    
    class Meta:
        model = QKDSession
        fields = [
            'id', 'session_id', 'sender_email', 'recipient_email',
            'key_manager', 'key_manager_name', 'status', 'created_at',
            'expires_at', 'completed_at', 'encryption_algorithm',
            'key_derivation_rounds', 'available_keys_count', 'consumed_keys_count'
        ]
        read_only_fields = ['session_id', 'created_at', 'completed_at']
    
    def get_available_keys_count(self, obj):
        """Count available keys in session"""
        from django.utils import timezone
        return obj.shared_keys.filter(
            status='available',
            expires_at__gt=timezone.now()
        ).count()
    
    def get_consumed_keys_count(self, obj):
        """Count consumed keys in session"""
        return obj.shared_keys.filter(status='consumed').count()


class QuantumEncryptedEmailSerializer(serializers.ModelSerializer):
    email_subject = serializers.CharField(source='email.subject', read_only=True)
    email_from = serializers.CharField(source='email.from_address', read_only=True)
    session_id = serializers.CharField(source='qkd_session.session_id', read_only=True)
    
    class Meta:
        model = QuantumEncryptedEmail
        fields = [
            'id', 'email', 'email_subject', 'email_from', 'qkd_session',
            'session_id', 'encryption_algorithm', 'quantum_security_level',
            'key_consumption_timestamp', 'forward_secrecy_enabled',
            'integrity_hash'
        ]
        read_only_fields = [
            'encrypted_subject', 'encrypted_body_text', 'encrypted_body_html',
            'key_derivation_salt', 'initialization_vector', 'quantum_signature'
        ]  # Sensitive encrypted data


class ExternalEmailProviderSerializer(serializers.ModelSerializer):
    provider_display_name = serializers.CharField(source='get_provider_type_display', read_only=True)
    connection_status = serializers.SerializerMethodField()
    
    class Meta:
        model = ExternalEmailProvider
        fields = [
            'id', 'provider_type', 'provider_display_name', 'email_address',
            'imap_server', 'imap_port', 'imap_use_ssl', 'smtp_server',
            'smtp_port', 'smtp_use_ssl', 'smtp_use_tls', 'username',
            'qkd_enabled', 'preferred_key_manager', 'is_active',
            'created_at', 'connection_status'
        ]
        read_only_fields = ['created_at', 'oauth2_expires_at']
        extra_kwargs = {
            'password': {'write_only': True},
            'oauth2_token': {'write_only': True},
            'oauth2_refresh_token': {'write_only': True}
        }
    
    def get_connection_status(self, obj):
        """Get connection status indicator"""
        if not obj.is_active:
            return 'disabled'
        
        # Check OAuth2 token expiry
        if obj.oauth2_token and obj.oauth2_expires_at:
            from django.utils import timezone
            if obj.oauth2_expires_at <= timezone.now():
                return 'token_expired'
        
        return 'active'


class QuantumEmailSendSerializer(serializers.Serializer):
    """Serializer for sending quantum-encrypted emails"""
    sender_email = serializers.EmailField()
    recipient_email = serializers.EmailField()
    subject = serializers.CharField(max_length=998)
    body_text = serializers.CharField()
    body_html = serializers.CharField(required=False, allow_blank=True)
    key_manager_id = serializers.IntegerField(required=False)
    
    def validate_sender_email(self, value):
        """Validate sender has configured external provider"""
        if not ExternalEmailProvider.objects.filter(
            email_address=value,
            is_active=True
        ).exists():
            raise serializers.ValidationError(
                f"No active external email provider configured for {value}"
            )
        return value
    
    def validate_key_manager_id(self, value):
        """Validate key manager exists and is active"""
        if value and not QKDKeyManager.objects.filter(
            id=value,
            is_active=True
        ).exists():
            raise serializers.ValidationError("Invalid or inactive Key Manager")
        return value