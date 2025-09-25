from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponseNotAllowed
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.core.mail import send_mail
from django.conf import settings
from django.db import transaction
import dns.resolver
import secrets
import json
import logging
from datetime import datetime
from .models import Domain, EmailAccount, Email, AllowedDomain
from .serializers import DomainSerializer, EmailAccountSerializer, EmailSerializer
from .smtp.security import DKIMSigner

logger = logging.getLogger(__name__)

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


# Email Client Views
def email_login(request):
    """Email client login view"""
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Check if email account exists and validate password
        try:
            email_account = EmailAccount.objects.get(email_address=email)
            if email_account.check_password(password):
                # Update last login time
                from django.utils import timezone
                email_account.last_login = timezone.now()
                email_account.save()
                
                request.session['user_email'] = email
                request.session['user_id'] = email_account.id
                messages.success(request, f'Successfully logged in as {email_account.full_name}')
                return redirect('email_client:inbox')
            else:
                messages.error(request, 'Invalid password. Please try again.')
        except EmailAccount.DoesNotExist:
            messages.error(request, 'Email account not found. Please check your email address or register a new account.')
    
    return render(request, 'email_core/login.html')


def email_register(request):
    """Email client registration view"""
    from .models import AllowedDomain
    
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        username = request.POST.get('username')
        selected_domain = request.POST.get('selected_domain')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        # Validation
        if not all([full_name, username, selected_domain, password, confirm_password]):
            messages.error(request, 'All fields are required.')
        elif password != confirm_password:
            messages.error(request, 'Passwords do not match.')
        elif len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
        else:
            # Check if domain is allowed
            try:
                allowed_domain = AllowedDomain.objects.get(domain_name=selected_domain, is_active=True)
            except AllowedDomain.DoesNotExist:
                messages.error(request, 'Selected domain is not available for registration.')
                return render(request, 'email_core/register.html', {
                    'allowed_domains': AllowedDomain.objects.filter(is_active=True)
                })
            
            email_address = f"{username}@{selected_domain}"
            
            # Check if email already exists
            if EmailAccount.objects.filter(email_address=email_address).exists():
                messages.error(request, f'Email address {email_address} is already taken. Please choose a different username.')
            else:
                try:
                    with transaction.atomic():
                        # Create or get domain (for legacy compatibility)
                        from django.contrib.auth.models import User
                        admin_user = User.objects.filter(is_superuser=True).first()
                        if not admin_user:
                            admin_user = User.objects.create_user('admin', 'admin@localhost', 'admin')
                            admin_user.is_superuser = True
                            admin_user.save()
                        
                        domain, created = Domain.objects.get_or_create(
                            domain_name=selected_domain,
                            defaults={
                                'user': admin_user,
                                'verification_token': secrets.token_urlsafe(32),
                                'is_verified': True
                            }
                        )
                        
                        # Create email account
                        email_account = EmailAccount.objects.create(
                            full_name=full_name,
                            email_address=email_address,
                            domain=domain,
                            allowed_domain=allowed_domain,
                            is_active=True
                        )
                        email_account.set_password(password)
                        email_account.save()
                        
                        messages.success(request, f'Account created successfully! You can now login as {email_address}')
                        return redirect('email_client:login')
                        
                except Exception as e:
                    messages.error(request, f'Failed to create account: {str(e)}')
    
    # Get allowed domains for the form
    allowed_domains = AllowedDomain.objects.filter(is_active=True).order_by('domain_name')
    
    return render(request, 'email_core/register.html', {
        'allowed_domains': allowed_domains
    })


def email_logout(request):
    """Email client logout view"""
    request.session.flush()
    messages.success(request, 'Successfully logged out')
    return redirect('email_client:login')


def inbox(request):
    """Email client inbox view with quantum email support"""
    if 'user_email' not in request.session:
        return redirect('email_client:login')
    
    user_email = request.session.get('user_email')
    
    try:
        email_account = EmailAccount.objects.get(email_address=user_email)
        
        # Get regular emails
        all_emails = Email.objects.all().order_by('-received_at')[:100]
        regular_emails = []
        
        for email in all_emails:
            to_addresses = email.get_to_addresses_list()
            if user_email in to_addresses:
                # Add the to_addresses as a property for template use
                email.to_addresses = to_addresses
                email.is_quantum = False
                regular_emails.append(email)
        
        # Get quantum emails
        from .models import RealQuantumEmail
        quantum_emails = RealQuantumEmail.objects.filter(
            recipient_email=user_email
        ).order_by('-created_at')[:50]
        
        # Convert quantum emails to display format
        quantum_email_list = []
        for qemail in quantum_emails:
            # Create a pseudo-email object for template compatibility
            class QuantumEmailDisplay:
                def __init__(self, qemail):
                    self.id = str(qemail.email_id)
                    self.subject = "🔒 Quantum Encrypted Email"  # Don't decrypt in list view
                    self.from_address = qemail.sender_email
                    self.to_addresses = [qemail.recipient_email]
                    self.received_at = qemail.created_at
                    self.is_read = qemail.status in ['decrypted', 'delivered']
                    self.is_quantum = True
                    self.quantum_security_level = qemail.quantum_security_level
                    self.body_text = ""  # Don't show body in list view
                    self.body_html = ""
            
            quantum_email_list.append(QuantumEmailDisplay(qemail))
        
        # Combine and sort all emails by date
        all_inbox_emails = regular_emails + quantum_email_list
        all_inbox_emails.sort(key=lambda x: x.received_at, reverse=True)
        
        return render(request, 'email_core/inbox.html', {
            'emails': all_inbox_emails[:50],  # Limit to 50 most recent
            'user_account': email_account
        })
    except EmailAccount.DoesNotExist:
        messages.error(request, 'Email account not found')
        return redirect('email_client:login')


@require_http_methods(["POST"])
def send_email(request):
    """Send email via client"""
    if 'user_email' not in request.session:
        return JsonResponse({'success': False, 'error': 'Not logged in'}, status=401)
    
    from_email = request.session.get('user_email')
    to_email = request.POST.get('to_address')
    subject = request.POST.get('subject')
    message = request.POST.get('message')
    
    if not all([to_email, subject, message]):
        return JsonResponse({'success': False, 'error': 'All fields are required'})
    
    try:
        # Check if recipient exists
        recipient_account = EmailAccount.objects.get(email_address=to_email)
        
        # Create email record in database
        with transaction.atomic():
            email = Email.objects.create(
                message_id=f"<{secrets.token_urlsafe(16)}@localhost>",
                from_address=from_email,
                subject=subject,
                body_text=message,
                size_bytes=len(message.encode('utf-8')),
                received_at=datetime.now(),
                folder='inbox'
            )
            # Set to_addresses using the helper method
            email.set_to_addresses_list([to_email])
            email.save()
            
            # Try to send via SMTP (optional, for MailHog capture)
            try:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=from_email,
                    recipient_list=[to_email],
                    fail_silently=True
                )
            except Exception as smtp_error:
                # SMTP failed but we still have the email in database
                print(f"SMTP sending failed: {smtp_error}")
        
        return JsonResponse({'success': True, 'message': 'Email sent successfully'})
        
    except EmailAccount.DoesNotExist:
        return JsonResponse({'success': False, 'error': f'Recipient {to_email} not found'})
    except Exception as e:
        print(f"Error sending email: {e}")
        return JsonResponse({'success': False, 'error': 'Failed to send email'})


def get_email(request, email_id):
    """Get email details as JSON with quantum decryption support"""
    
    # Debug: Log session info
    logger.info(f"get_email called for email_id: {email_id}")
    logger.info(f"Session keys: {list(request.session.keys())}")
    logger.info(f"user_email in session: {request.session.get('user_email')}")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Request headers: {dict(request.headers)}")
    
    if 'user_email' not in request.session:
        logger.warning("No user_email in session")
        return JsonResponse({'error': 'Not logged in', 'debug': {
            'session_keys': list(request.session.keys()),
            'has_sessionid': 'sessionid' in request.COOKIES,
            'cookies': list(request.COOKIES.keys())
        }}, status=401)
    
def get_email(request, email_id):
    """Get email details as JSON with quantum decryption support"""
    
    # Debug: Log session info
    logger.info(f"get_email called for email_id: {email_id}")
    logger.info(f"Session keys: {list(request.session.keys())}")
    logger.info(f"user_email in session: {request.session.get('user_email')}")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Request headers: {dict(request.headers)}")
    
    if 'user_email' not in request.session:
        logger.warning("No user_email in session")
        return JsonResponse({'error': 'Not logged in', 'debug': {
            'session_keys': list(request.session.keys()),
            'has_sessionid': 'sessionid' in request.COOKIES,
            'cookies': list(request.COOKIES.keys())
        }}, status=401)
    
    user_email = request.session.get('user_email')
    logger.info(f"Authenticated user_email: {user_email}")
    
    try:
        # First try quantum email via regular email lookup
        from .models import RealQuantumEmail, QKDKey
        import json
        
        try:
            # Check if this regular email has quantum data
            email = Email.objects.get(id=email_id)
            if hasattr(email, 'real_quantum_data') and email.real_quantum_data.exists():
                quantum_email = email.real_quantum_data.first()
                
                # Check if user has access to this quantum email
                to_addresses = email.get_to_addresses_list()
                if user_email not in to_addresses:
                    return JsonResponse({'error': 'Access denied'}, status=403)
                
                # Try to decrypt the email content using the real crypto system
                try:
                    # Parse encrypted data (stored as JSON strings)
                    encrypted_subject = json.loads(quantum_email.encrypted_subject)
                    encrypted_body = json.loads(quantum_email.encrypted_body_text)
                    encrypted_html = None
                    if quantum_email.encrypted_body_html:
                        encrypted_html = json.loads(quantum_email.encrypted_body_html)
                    
                    # Use the RealQuantumCrypto class for decryption
                    from .qkd.real_crypto import RealQuantumCrypto
                    crypto = RealQuantumCrypto()
                    
                    # Decrypt each component using its own key ID
                    # Subject decryption
                    subject_key_id = encrypted_subject.get('quantum_key_id')
                    subject_key = QKDKey.objects.get(key_id=subject_key_id)
                    if subject_key.status not in ['available', 'consumed']:
                        raise Exception(f"Subject key {subject_key_id} is not usable (status: {subject_key.status})")
                    decrypted_subject = crypto.decrypt_with_quantum_key(encrypted_subject, subject_key)
                    
                    # Body decryption
                    body_key_id = encrypted_body.get('quantum_key_id')
                    body_key = QKDKey.objects.get(key_id=body_key_id)
                    if body_key.status not in ['available', 'consumed']:
                        raise Exception(f"Body key {body_key_id} is not usable (status: {body_key.status})")
                    decrypted_body = crypto.decrypt_with_quantum_key(encrypted_body, body_key)
                    
                    # HTML decryption
                    decrypted_html = None
                    if encrypted_html:
                        html_key_id = encrypted_html.get('quantum_key_id')
                        html_key = QKDKey.objects.get(key_id=html_key_id)
                        if html_key.status not in ['available', 'consumed']:
                            raise Exception(f"HTML key {html_key_id} is not usable (status: {html_key.status})")
                        decrypted_html = crypto.decrypt_with_quantum_key(encrypted_html, html_key)
                    
                    logger.info(f"Successfully decrypted quantum email {email.id}")
                    
                    return JsonResponse({
                        'id': email.id,
                        'subject': decrypted_subject,
                        'from_address': quantum_email.sender_email,
                        'to_addresses': [quantum_email.recipient_email],
                        'body_text': decrypted_body,
                        'body_html': decrypted_html,
                        'received_at': email.received_at.isoformat(),
                        'is_read': email.is_read,
                        'is_quantum': True,
                        'quantum_security_level': quantum_email.quantum_security_level,
                        'encryption_algorithm': quantum_email.encryption_algorithm
                    })
                    
                except Exception as decrypt_error:
                    logger.error(f"Quantum email decryption failed: {decrypt_error}")
                    return JsonResponse({
                        'error': 'Decryption failed',
                        'details': str(decrypt_error),
                        'is_quantum': True,
                        'from_address': quantum_email.sender_email,
                        'to_addresses': [quantum_email.recipient_email]
                    }, status=500)
            
            # Handle regular (non-quantum) email
            to_addresses = email.get_to_addresses_list()
            
            # Check if user has access to this email
            if user_email not in to_addresses:
                return JsonResponse({'error': 'Access denied'}, status=403)
            
            return JsonResponse({
                'id': email.id,
                'subject': email.subject,
                'from_address': email.from_address,
                'to_addresses': to_addresses,
                'body_text': email.body_text,
                'body_html': email.body_html,
                'received_at': email.received_at.isoformat(),
                'is_read': email.is_read,
                'is_quantum': False
            })
        except Email.DoesNotExist:
            pass
            
        return JsonResponse({'error': 'Email not found'}, status=404)
        
    except Exception as e:
        return JsonResponse({'error': 'Server error', 'details': str(e)}, status=500)


@require_http_methods(["POST"])
def mark_email_read(request, email_id):
    """Mark email as read (both regular and quantum emails)"""
    if 'user_email' not in request.session:
        return JsonResponse({'error': 'Not logged in'}, status=401)
    
    user_email = request.session.get('user_email')
    
    try:
        # Try regular email first
        try:
            # Check if email_id is numeric for regular emails
            email = Email.objects.get(id=int(email_id))
            to_addresses = email.get_to_addresses_list()
            
            # Check if user has access to this email
            if user_email not in to_addresses:
                return JsonResponse({'error': 'Access denied'}, status=403)
            
            email.is_read = True
            email.save()
            return JsonResponse({'success': True})
        except (Email.DoesNotExist, ValueError):
            pass
        
        # Try quantum email
        from .models import RealQuantumEmail
        try:
            quantum_email = RealQuantumEmail.objects.get(email_id=email_id)
            
            # Check if user has access to this quantum email
            if user_email != quantum_email.recipient_email:
                return JsonResponse({'error': 'Access denied'}, status=403)
            
            # Update quantum email status to indicate it's been read/decrypted
            quantum_email.status = 'decrypted'
            quantum_email.save()
            return JsonResponse({'success': True})
        except RealQuantumEmail.DoesNotExist:
            pass
            
        return JsonResponse({'error': 'Email not found'}, status=404)
        
    except Exception as e:
        return JsonResponse({'error': 'Server error', 'details': str(e)}, status=500)


def inbox_count(request):
    """Get inbox count for auto-refresh"""
    if 'user_email' not in request.session:
        return JsonResponse({'error': 'Not logged in'}, status=401)
    
    user_email = request.session.get('user_email')
    
    # Count emails where user is in to_addresses
    all_emails = Email.objects.all()
    count = 0
    for email in all_emails:
        to_addresses = email.get_to_addresses_list()
        if user_email in to_addresses:
            count += 1
    
    return JsonResponse({'count': count})


# QKD Status Endpoints (Public - No authentication required for basic status)
def qkd_status(request):
    """Get basic QKD system status for frontend"""
    try:
        from .models import QKDKeyManager, QKDKey, QKDSession, RealQuantumEmail
        
        # Get basic stats
        active_key_managers = QKDKeyManager.objects.filter(is_active=True).count()
        total_keys = QKDKey.objects.count()
        available_keys = QKDKey.objects.filter(status='available').count()
        consumed_keys = QKDKey.objects.filter(status='consumed').count()
        active_sessions = QKDSession.objects.filter(status='active').count()
        quantum_emails = RealQuantumEmail.objects.count()
        
        # Calculate key availability percentage
        key_availability = (available_keys / total_keys * 100) if total_keys > 0 else 0
        
        # Determine overall system status
        if active_key_managers > 0 and available_keys > 5:
            system_status = 'active'
            status_text = 'QKD Active'
        elif active_key_managers > 0 and available_keys > 0:
            system_status = 'low_keys'
            status_text = 'QKD Low Keys'
        elif active_key_managers > 0:
            system_status = 'no_keys'
            status_text = 'QKD No Keys'
        else:
            system_status = 'inactive'
            status_text = 'QKD Inactive'
        
        return JsonResponse({
            'status': system_status,
            'status_text': status_text,
            'active_key_managers': active_key_managers,
            'total_keys': total_keys,
            'available_keys': available_keys,
            'consumed_keys': consumed_keys,
            'key_availability_percent': round(key_availability, 1),
            'active_sessions': active_sessions,
            'quantum_emails_sent': quantum_emails,
            'quantum_security_level': 99.9,
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'status_text': 'QKD Error',
            'error': str(e),
            'active_key_managers': 0,
            'available_keys': 0,
            'active_sessions': 0
        })


def qkd_key_managers(request):
    """Get basic key manager info for frontend"""
    try:
        from .models import QKDKeyManager
        
        key_managers = []
        for km in QKDKeyManager.objects.filter(is_active=True):
            total_keys = km.keys.count()
            available_keys = km.keys.filter(status='available').count()
            
            key_managers.append({
                'id': km.id,
                'name': km.name,
                'base_url': km.base_url,
                'is_simulated': km.is_simulated,
                'is_active': km.is_active,
                'key_statistics': {
                    'total_keys': total_keys,
                    'available_keys': available_keys,
                    'consumed_keys': total_keys - available_keys
                }
            })
        
        return JsonResponse({
            'key_managers': key_managers,
            'total_managers': len(key_managers)
        })
        
    except Exception as e:
        logger.error(f"Error getting key managers: {e}")
        return JsonResponse({
            'error': str(e),
            'key_managers': [],
            'total_managers': 0
        })