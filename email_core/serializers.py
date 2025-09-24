from rest_framework import serializers
from .models import Domain, EmailAccount, Email, EmailAttachment

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