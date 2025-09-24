from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
import dns.resolver
import secrets
import json
from .models import Domain, EmailAccount, Email
from .serializers import DomainSerializer, EmailAccountSerializer, EmailSerializer
from .smtp.security import DKIMSigner

class DomainViewSet(viewsets.ModelViewSet):
    serializer_class = DomainSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Domain.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        """Create domain with generated keys"""
        from django.conf import settings
        
        domain = serializer.save(
            user=self.request.user,
            verification_token=secrets.token_urlsafe(32)
        )
        
        # Generate DKIM keys
        domain.generate_dkim_keys()
        
        # Generate SPF record
        domain.generate_spf_record(settings.EMAIL_SERVICE_CONFIG['SERVER_IP'])
        
        domain.save()
    
    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """Verify domain ownership"""
        domain = self.get_object()
        
        try:
            # Check MX record
            mx_records = dns.resolver.resolve(domain.domain_name, 'MX')
            mx_valid = False
            
            from django.conf import settings
            expected_mx = settings.EMAIL_SERVICE_CONFIG['SERVER_HOSTNAME']
            
            for mx in mx_records:
                if str(mx.exchange).rstrip('.') == expected_mx:
                    mx_valid = True
                    break
            
            if mx_valid:
                # Check TXT record for verification token
                txt_records = dns.resolver.resolve(domain.domain_name, 'TXT')
                for txt in txt_records:
                    if domain.verification_token in str(txt):
                        domain.is_verified = True
                        domain.save()
                        return Response({'status': 'verified'})
            
            return Response(
                {'error': 'DNS records not properly configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except Exception as e:
            return Response(
                {'error': f'Verification failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['get'])
    def dns_check(self, request, pk=None):
        """Check current DNS configuration"""
        domain = self.get_object()
        results = {}
        
        try:
            # Check MX
            mx_records = dns.resolver.resolve(domain.domain_name, 'MX')
            results['mx'] = [{'priority': mx.preference, 'host': str(mx.exchange)} 
                           for mx in mx_records]
        except:
            results['mx'] = []
        
        try:
            # Check SPF
            txt_records = dns.resolver.resolve(domain.domain_name, 'TXT')
            results['spf'] = [str(txt) for txt in txt_records if 'v=spf1' in str(txt)]
        except:
            results['spf'] = []
        
        try:
            # Check DKIM
            dkim_domain = f"{domain.dkim_selector}._domainkey.{domain.domain_name}"
            dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
            results['dkim'] = [str(txt) for txt in dkim_records]
        except:
            results['dkim'] = []
        
        try:
            # Check DMARC
            dmarc_domain = f"_dmarc.{domain.domain_name}"
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            results['dmarc'] = [str(txt) for txt in dmarc_records]
        except:
            results['dmarc'] = []
        
        return Response(results)

class EmailAccountViewSet(viewsets.ModelViewSet):
    serializer_class = EmailAccountSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return EmailAccount.objects.filter(
            domain__user=self.request.user
        )
    
    @action(detail=False, methods=['post'])
    def send_email(self, request):
        """Send an email"""
        from email.message import EmailMessage
        import smtplib
        
        email_address = request.data.get('from')
        to_addresses = request.data.get('to', [])
        subject = request.data.get('subject', '')
        body = request.data.get('body', '')
        
        # Verify sender account
        try:
            account = EmailAccount.objects.get(
                email_address=email_address,
                domain__user=request.user
            )
        except EmailAccount.DoesNotExist:
            return Response(
                {'error': 'Email account not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Create email message
        msg = EmailMessage()
        msg['From'] = email_address
        msg['To'] = ', '.join(to_addresses)
        msg['Subject'] = subject
        msg.set_content(body)
        
        # Sign with DKIM
        domain_name = email_address.split('@')[1]
        signed_message = DKIMSigner.sign_email(
            msg.as_bytes(),
            domain_name
        )
        
        # Send email
        try:
            from django.conf import settings
            with smtplib.SMTP(
                settings.EMAIL_SERVICE_CONFIG['SERVER_HOSTNAME'],
                settings.EMAIL_SERVICE_CONFIG['SMTP_PORT']
            ) as server:
                server.send_message(msg)
            
            # Save to sent folder
            Email.objects.create(
                email_account=account,
                message_id=msg['Message-ID'],
                from_address=email_address,
                to_addresses=json.dumps(to_addresses),
                subject=subject,
                body_text=body,
                size_bytes=len(signed_message),
                is_sent=True,
                folder='SENT'
            )
            
            return Response({'status': 'sent'})
            
        except Exception as e:
            return Response(
                {'error': f'Failed to send email: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class EmailViewSet(viewsets.ModelViewSet):
    serializer_class = EmailSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Email.objects.filter(
            email_account__domain__user=self.request.user
        )
    
    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        """Mark email as read"""
        email = self.get_object()
        email.is_read = True
        email.save()
        return Response({'status': 'marked as read'})
    
    @action(detail=True, methods=['get'])
    def download_attachment(self, request, pk=None):
        """Download email attachment"""
        from django.http import HttpResponse
        
        email = self.get_object()
        attachment_id = request.query_params.get('attachment_id')
        
        if not attachment_id:
            return Response(
                {'error': 'attachment_id required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            attachment = email.attachments.get(id=attachment_id)
            response = HttpResponse(
                attachment.file_data,
                content_type=attachment.content_type
            )
            response['Content-Disposition'] = f'attachment; filename="{attachment.filename}"'
            return response
        except EmailAttachment.DoesNotExist:
            return Response(
                {'error': 'Attachment not found'},
                status=status.HTTP_404_NOT_FOUND
            )