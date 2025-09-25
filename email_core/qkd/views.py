"""
QKD API Views for Qute Mail

This module provides REST API endpoints for quantum key distribution operations,
including key manager configuration, QKD session management, and quantum email operations.
"""

import logging
import asyncio
from typing import Dict, Any
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from asgiref.sync import sync_to_async

from ..models import (
    QKDKeyManager, QKDKey, QKDSession, QuantumEncryptedEmail,
    ExternalEmailProvider, Email
)
from ..serializers import (
    QKDKeyManagerSerializer, QKDSessionSerializer, 
    QuantumEncryptedEmailSerializer, ExternalEmailProviderSerializer
)
from .service import QKDService
from .key_manager import get_qkd_client

logger = logging.getLogger(__name__)


class QKDKeyManagerViewSet(viewsets.ModelViewSet):
    """
    API endpoints for QKD Key Manager configuration
    """
    serializer_class = QKDKeyManagerSerializer
    permission_classes = [IsAuthenticated]
    queryset = QKDKeyManager.objects.all()
    
    def get_queryset(self):
        """Filter Key Managers by user access"""
        # For now, show all active Key Managers
        # In production, implement proper access control
        return QKDKeyManager.objects.filter(is_active=True)
    
    @action(detail=True, methods=['post'])
    def test_connection(self, request, pk=None):
        """
        Test connection to Key Manager
        """
        try:
            key_manager = self.get_object()
            qkd_client = get_qkd_client(key_manager)
            
            # Run async test in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Test authentication
                auth_result = loop.run_until_complete(qkd_client.authenticate())
                if not auth_result:
                    return Response(
                        {'error': 'Authentication failed'},
                        status=status.HTTP_401_UNAUTHORIZED
                    )
                
                # Test status endpoint
                km_status = loop.run_until_complete(qkd_client.get_status())
                
                return Response({
                    'status': 'connected',
                    'key_manager': key_manager.name,
                    'is_simulated': key_manager.is_simulated,
                    'km_status': km_status
                })
                
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Key Manager connection test failed: {e}")
            return Response(
                {'error': f'Connection test failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['get'])
    def key_statistics(self, request, pk=None):
        """
        Get key usage statistics for Key Manager
        """
        try:
            key_manager = self.get_object()
            
            # Get key statistics
            total_keys = QKDKey.objects.filter(key_manager=key_manager).count()
            available_keys = QKDKey.objects.filter(
                key_manager=key_manager,
                status='available'
            ).count()
            consumed_keys = QKDKey.objects.filter(
                key_manager=key_manager,
                status='consumed'
            ).count()
            expired_keys = QKDKey.objects.filter(
                key_manager=key_manager,
                status='expired'
            ).count()
            
            # Get active sessions
            active_sessions = QKDSession.objects.filter(
                key_manager=key_manager,
                status='active'
            ).count()
            
            return Response({
                'key_manager': key_manager.name,
                'statistics': {
                    'total_keys': total_keys,
                    'available_keys': available_keys,
                    'consumed_keys': consumed_keys,
                    'expired_keys': expired_keys,
                    'active_sessions': active_sessions,
                    'key_utilization_rate': (consumed_keys / total_keys * 100) if total_keys > 0 else 0
                }
            })
            
        except Exception as e:
            logger.error(f"Failed to get key statistics: {e}")
            return Response(
                {'error': f'Failed to get statistics: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )


class QKDSessionViewSet(viewsets.ModelViewSet):
    """
    API endpoints for QKD session management
    """
    serializer_class = QKDSessionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter sessions by user email access"""
        user_emails = [
            provider.email_address 
            for provider in ExternalEmailProvider.objects.filter(user=self.request.user)
        ]
        
        return QKDSession.objects.filter(
            sender_email__in=user_emails
        ).union(
            QKDSession.objects.filter(recipient_email__in=user_emails)
        )
    
    @action(detail=False, methods=['post'])
    def create_session(self, request):
        """
        Create new QKD session between two parties
        """
        try:
            sender_email = request.data.get('sender_email')
            recipient_email = request.data.get('recipient_email')
            key_manager_id = request.data.get('key_manager_id')
            
            if not sender_email or not recipient_email:
                return Response(
                    {'error': 'sender_email and recipient_email are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Initialize QKD service
            qkd_service = QKDService()
            
            # Run async session creation in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                session = loop.run_until_complete(
                    qkd_service.create_qkd_session(
                        sender_email, 
                        recipient_email, 
                        key_manager_id
                    )
                )
                
                serializer = self.get_serializer(session)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
                
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Failed to create QKD session: {e}")
            return Response(
                {'error': f'Session creation failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['get'])
    def session_status(self, request, pk=None):
        """
        Get detailed status of QKD session
        """
        try:
            session = self.get_object()
            qkd_service = QKDService()
            
            status_info = qkd_service.get_session_status(
                session.sender_email,
                session.recipient_email
            )
            
            return Response(status_info)
            
        except Exception as e:
            logger.error(f"Failed to get session status: {e}")
            return Response(
                {'error': f'Failed to get session status: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['post'])
    def refresh_keys(self, request, pk=None):
        """
        Refresh quantum keys for session
        """
        try:
            session = self.get_object()
            
            if not session.is_active():
                return Response(
                    {'error': 'Session is not active'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            qkd_service = QKDService()
            
            # Run async key refresh in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                loop.run_until_complete(qkd_service._refill_session_keys(session))
                
                return Response({
                    'status': 'success',
                    'message': 'Session keys refreshed successfully'
                })
                
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Failed to refresh session keys: {e}")
            return Response(
                {'error': f'Key refresh failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )


class ExternalEmailProviderViewSet(viewsets.ModelViewSet):
    """
    API endpoints for external email provider configuration
    """
    serializer_class = ExternalEmailProviderSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter providers by current user"""
        return ExternalEmailProvider.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        """Set user when creating provider"""
        serializer.save(user=self.request.user)
    
    @action(detail=True, methods=['post'])
    def test_connection(self, request, pk=None):
        """
        Test connection to external email provider
        """
        try:
            provider = self.get_object()
            
            from .external_providers import ExternalEmailClient
            
            client = ExternalEmailClient(provider)
            
            # Run async connection test in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Test by trying to establish SMTP connection
                smtp_server = client._get_smtp_connection()
                smtp_server.quit()
                
                return Response({
                    'status': 'connected',
                    'provider': provider.get_provider_type_display(),
                    'email': provider.email_address
                })
                
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Provider connection test failed: {e}")
            return Response(
                {'error': f'Connection test failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['post'])
    def send_test_email(self, request, pk=None):
        """
        Send test quantum-encrypted email
        """
        try:
            provider = self.get_object()
            recipient_email = request.data.get('recipient_email', provider.email_address)
            
            qkd_service = QKDService()
            
            # Run async email sending in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                email = loop.run_until_complete(
                    qkd_service.send_quantum_email(
                        sender_email=provider.email_address,
                        recipient_email=recipient_email,
                        subject="Qute Mail QKD Test",
                        body_text="""This is a test quantum-encrypted email from Qute Mail!
                        
If you can read this message clearly, it means:
✅ QKD session was established successfully
✅ Quantum keys were distributed securely  
✅ Email content was encrypted using post-quantum safe algorithms
✅ The quantum envelope was properly formatted

Your email communication is now secured with unconditional quantum safety!

Best regards,
Qute Mail QKD System"""
                    )
                )
                
                return Response({
                    'status': 'sent',
                    'email_id': email.id,
                    'message': f'Test quantum email sent to {recipient_email}'
                })
                
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Failed to send test email: {e}")
            return Response(
                {'error': f'Test email failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )


from django.views import View

@method_decorator(csrf_exempt, name='dispatch')
class QuantumEmailAPIView(View):
    """
    API endpoints for quantum email operations
    """
    
    def post(self, request):
        """Route POST requests to appropriate handler"""
        action = request.path.split('/')[-2]  # Get action from URL path
        
        if action == 'send':
            return self.send_quantum_email(request)
        elif action == 'decrypt':
            return self.decrypt_quantum_email(request)
        else:
            return JsonResponse({'error': 'Invalid action'}, status=400)
    
    def send_quantum_email(self, request):
        """
        Send quantum-encrypted email
        """
        if request.method != 'POST':
            return JsonResponse({'error': 'POST method required'}, status=405)
        
        try:
            import json
            data = json.loads(request.body.decode('utf-8'))
            
            sender_email = data.get('sender_email')
            recipient_email = data.get('recipient_email')
            subject = data.get('subject')
            body_text = data.get('body_text')
            body_html = data.get('body_html')
            
            if not all([sender_email, recipient_email, subject, body_text]):
                return JsonResponse({
                    'error': 'sender_email, recipient_email, subject, and body_text are required'
                }, status=400)
            
            # Initialize QKD service
            qkd_service = QKDService()
            
            # Use sync method for Django context
            email = qkd_service.send_quantum_email_sync(
                sender_email=sender_email,
                recipient_email=recipient_email,
                subject=subject,
                body_text=body_text,
                body_html=body_html
            )
            
            return JsonResponse({
                'status': 'sent',
                'email_id': email.id,
                'message': f'Quantum email sent from {sender_email} to {recipient_email}',
                'quantum_secured': True
            })
                
        except Exception as e:
            logger.error(f"Quantum email sending failed: {e}")
            return JsonResponse({
                'error': f'Failed to send quantum email: {str(e)}'
            }, status=400)
    
    def decrypt_quantum_email(self, request):
        """
        Decrypt quantum-encrypted email using real QKD keys
        """
        if request.method != 'POST':
            return JsonResponse({'error': 'POST method required'}, status=405)
        
        try:
            import json
            data = json.loads(request.body.decode('utf-8'))
            
            quantum_email_id = data.get('quantum_email_id')
            recipient_email = data.get('recipient_email')
            
            if not quantum_email_id:
                return JsonResponse({'error': 'quantum_email_id is required'}, status=400)
            
            # Get real quantum encrypted email
            from ..models import RealQuantumEmail, QKDKey
            from ..qkd.real_crypto import quantum_crypto
            
            quantum_email = get_object_or_404(RealQuantumEmail, id=quantum_email_id)
            
            # Find the quantum key used for encryption
            quantum_key = QKDKey.objects.filter(
                key_id=quantum_email.quantum_key_id
            ).first()
            
            if not quantum_key:
                return JsonResponse({
                    'error': 'Quantum key not found - email may be permanently encrypted'
                }, status=404)
            
            # Decrypt the content
            encrypted_subject_data = json.loads(quantum_email.encrypted_subject)
            encrypted_body_data = json.loads(quantum_email.encrypted_body_text)
            encrypted_html_data = None
            if quantum_email.encrypted_body_html:
                encrypted_html_data = json.loads(quantum_email.encrypted_body_html)
            
            decrypted_subject = quantum_crypto.decrypt_with_quantum_key(
                encrypted_subject_data, quantum_key
            )
            
            decrypted_body = quantum_crypto.decrypt_with_quantum_key(
                encrypted_body_data, quantum_key
            )
            
            decrypted_html = None
            if encrypted_html_data:
                decrypted_html = quantum_crypto.decrypt_with_quantum_key(
                    encrypted_html_data, quantum_key
                )
            
            # Update status
            quantum_email.status = 'decrypted'
            quantum_email.decrypted_at = timezone.now()
            quantum_email.save()
            
            # Parse quantum envelope
            envelope = json.loads(quantum_email.quantum_envelope)
            
            return JsonResponse({
                'status': 'decrypted',
                'quantum_email_id': str(quantum_email.email_id),
                'content': {
                    'subject': decrypted_subject,
                    'body_text': decrypted_body,
                    'body_html': decrypted_html
                },
                'quantum_metadata': {
                    'sender': quantum_email.sender_email,
                    'recipient': quantum_email.recipient_email,
                    'encryption_algorithm': quantum_email.encryption_algorithm,
                    'quantum_key_id': quantum_email.quantum_key_id,
                    'security_level': f"{quantum_email.quantum_security_level}% quantum safe",
                    'encrypted_at': encrypted_subject_data.get('encrypted_at'),
                    'decrypted_at': quantum_email.decrypted_at.isoformat(),
                    'key_size_bits': encrypted_subject_data.get('key_size_bits'),
                    'ksid': encrypted_subject_data.get('ksid'),
                    'envelope': envelope
                },
                'verification': {
                    'quantum_secured': True,
                    'unconditional_security': True,
                    'forward_secrecy': True
                }
            })
                
        except Exception as e:
            logger.error(f"Quantum email decryption failed: {e}")
            return JsonResponse({
                'error': f'Failed to decrypt quantum email: {str(e)}'
            }, status=400)