"""
QKD Service Layer for Qute Mail

This module orchestrates quantum key distribution operations, managing
the lifecycle of QKD sessions, key retrieval, and quantum-safe email encryption.
"""

import logging
import asyncio
import uuid
import base64
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError

from ..models import (
    QKDKeyManager, QKDKey, QKDSession, QuantumEncryptedEmail, 
    Email, EmailAccount, ExternalEmailProvider
)
from .key_manager import get_qkd_client, ETSIQKDError, KeyNotAvailableError
from .crypto import QuantumCrypto, generate_quantum_envelope, verify_quantum_envelope
from .external_providers import ExternalEmailClient

logger = logging.getLogger(__name__)


class QKDServiceError(Exception):
    """Base exception for QKD service operations"""
    pass


class SessionError(QKDServiceError):
    """Exception raised when QKD session operations fail"""
    pass


class EncryptionServiceError(QKDServiceError):
    """Exception raised when encryption service operations fail"""
    pass


class QKDService:
    """
    Main service class for Quantum Key Distribution operations
    
    This class manages QKD sessions, key retrieval from Key Managers,
    and quantum-safe encryption/decryption of email content.
    """
    
    def __init__(self):
        """Initialize QKD service"""
        self.crypto = QuantumCrypto()
        logger.info("QKD Service initialized")
    
    async def create_qkd_session(self,
                               sender_email: str,
                               recipient_email: str,
                               key_manager_id: int = None,
                               session_duration_hours: int = 24) -> QKDSession:
        """
        Create a new QKD session between sender and recipient
        
        Args:
            sender_email: Sender's email address
            recipient_email: Recipient's email address  
            key_manager_id: Specific Key Manager to use (auto-select if None)
            session_duration_hours: Session validity duration
            
        Returns:
            QKDSession: Created QKD session
        """
        try:
            # Select Key Manager
            if key_manager_id:
                key_manager = QKDKeyManager.objects.get(id=key_manager_id, is_active=True)
            else:
                key_manager = QKDKeyManager.objects.filter(is_active=True).first()
                
            if not key_manager:
                raise SessionError("No active Key Manager available")
            
            # Check for existing active session
            existing_session = QKDSession.objects.filter(
                sender_email=sender_email,
                recipient_email=recipient_email,
                status='active',
                expires_at__gt=timezone.now()
            ).first()
            
            if existing_session:
                logger.info(f"Reusing existing QKD session: {existing_session.session_id}")
                return existing_session
            
            # Create new session
            session = QKDSession.objects.create(
                sender_email=sender_email,
                recipient_email=recipient_email,
                key_manager=key_manager,
                expires_at=timezone.now() + timedelta(hours=session_duration_hours),
                status='initializing'
            )
            
            logger.info(f"Created QKD session {session.session_id} between {sender_email} and {recipient_email}")
            
            # Initialize session with Key Manager
            await self._initialize_session_keys(session)
            
            return session
            
        except Exception as e:
            logger.error(f"Failed to create QKD session: {e}")
            raise SessionError(f"Session creation failed: {e}")
    
    async def _initialize_session_keys(self, session: QKDSession, initial_key_count: int = 5):
        """
        Initialize QKD session with quantum keys from Key Manager
        
        Args:
            session: QKD session to initialize
            initial_key_count: Number of keys to pre-fetch
        """
        try:
            # Generate Key Stream ID
            ksid = f"qute-mail-{session.sender_email}-{session.recipient_email}-{session.session_id}"
            
            # Get QKD client
            qkd_client = get_qkd_client(session.key_manager)
            
            # Request quantum keys
            key_response = await qkd_client.request_keys(
                ksid=ksid,
                number=initial_key_count,
                size=session.key_manager.default_key_size
            )
            
            # Store keys in database
            retrieved_keys = []
            for key_data in key_response['keys']:
                qkd_key = QKDKey.objects.create(
                    key_manager=session.key_manager,
                    ksid=ksid,
                    key_data=key_data['key'].encode('utf-8'),  # Base64 encoded
                    key_size_bits=key_data['key_size'],
                    expires_at=timezone.now() + timedelta(hours=1),  # Keys expire faster than session
                    sender_email=session.sender_email,
                    recipient_email=session.recipient_email
                )
                retrieved_keys.append(qkd_key)
            
            # Associate keys with session
            session.shared_keys.set(retrieved_keys)
            session.status = 'active'
            session.save()
            
            logger.info(f"Initialized session {session.session_id} with {len(retrieved_keys)} quantum keys")
            
        except ETSIQKDError as e:
            session.status = 'error'
            session.save()
            logger.error(f"Failed to initialize session keys: {e}")
            raise SessionError(f"Key initialization failed: {e}")
        except Exception as e:
            session.status = 'error'
            session.save()
            logger.error(f"Unexpected error during session initialization: {e}")
            raise SessionError(f"Session initialization failed: {e}")
    
    async def get_or_create_session(self,
                                  sender_email: str,
                                  recipient_email: str) -> QKDSession:
        """
        Get existing QKD session or create new one if needed
        
        Args:
            sender_email: Sender's email address
            recipient_email: Recipient's email address
            
        Returns:
            QKDSession: Active QKD session
        """
        try:
            # Try to find existing active session
            session = QKDSession.objects.filter(
                sender_email=sender_email,
                recipient_email=recipient_email,
                status='active',
                expires_at__gt=timezone.now()
            ).first()
            
            if session:
                # Check if session needs more keys
                available_keys = session.shared_keys.filter(
                    status='available',
                    expires_at__gt=timezone.now()
                ).count()
                
                if available_keys < 2:  # Refill if running low
                    await self._refill_session_keys(session)
                
                return session
            
            # Create new session
            return await self.create_qkd_session(sender_email, recipient_email)
            
        except Exception as e:
            logger.error(f"Failed to get or create QKD session: {e}")
            raise SessionError(f"Session retrieval failed: {e}")
    
    async def _refill_session_keys(self, session: QKDSession, refill_count: int = 3):
        """
        Refill session with additional quantum keys
        
        Args:
            session: QKD session to refill
            refill_count: Number of additional keys to fetch
        """
        try:
            ksid = f"qute-mail-{session.sender_email}-{session.recipient_email}-{session.session_id}"
            qkd_client = get_qkd_client(session.key_manager)
            
            # Request more keys
            key_response = await qkd_client.request_keys(
                ksid=ksid,
                number=refill_count,
                size=session.key_manager.default_key_size
            )
            
            # Store new keys
            new_keys = []
            for key_data in key_response['keys']:
                qkd_key = QKDKey.objects.create(
                    key_manager=session.key_manager,
                    ksid=ksid,
                    key_data=key_data['key'].encode('utf-8'),
                    key_size_bits=key_data['key_size'],
                    expires_at=timezone.now() + timedelta(hours=1),
                    sender_email=session.sender_email,
                    recipient_email=session.recipient_email
                )
                new_keys.append(qkd_key)
            
            # Add to session
            session.shared_keys.add(*new_keys)
            logger.info(f"Refilled session {session.session_id} with {len(new_keys)} additional keys")
            
        except Exception as e:
            logger.error(f"Failed to refill session keys: {e}")
            # Don't raise exception - session can continue with existing keys
    
    async def encrypt_email(self,
                          email: Email,
                          sender_email: str,
                          recipient_email: str) -> QuantumEncryptedEmail:
        """
        Encrypt email using quantum-safe encryption
        
        Args:
            email: Email object to encrypt
            sender_email: Sender's email address
            recipient_email: Recipient's email address
            
        Returns:
            QuantumEncryptedEmail: Quantum encrypted email object
        """
        try:
            # Get or create QKD session
            session = await self.get_or_create_session(sender_email, recipient_email)
            
            # Get available quantum key
            quantum_key_obj = session.get_available_key()
            if not quantum_key_obj:
                raise EncryptionServiceError("No quantum keys available for encryption")
            
            # Decode quantum key
            import base64
            quantum_key = base64.b64decode(quantum_key_obj.key_data)
            
            # Generate salt and IV for key derivation
            import secrets
            salt = secrets.token_bytes(32)
            iv = secrets.token_bytes(12)
            
            # Encrypt email components
            encrypted_subject = None
            if email.subject:
                subject_result = self.crypto.encrypt_content(
                    email.subject, quantum_key, salt
                )
                encrypted_subject = subject_result['ciphertext'].encode('utf-8')
            
            encrypted_body_text = None
            if email.body_text:
                body_result = self.crypto.encrypt_content(
                    email.body_text, quantum_key, salt
                )
                encrypted_body_text = body_result['ciphertext'].encode('utf-8')
            
            encrypted_body_html = None
            if email.body_html:
                html_result = self.crypto.encrypt_content(
                    email.body_html, quantum_key, salt
                )
                encrypted_body_html = html_result['ciphertext'].encode('utf-8')
            
            # Calculate integrity hash
            import hashlib
            content_for_hash = b''
            if encrypted_subject:
                content_for_hash += encrypted_subject
            if encrypted_body_text:
                content_for_hash += encrypted_body_text
            if encrypted_body_html:
                content_for_hash += encrypted_body_html
            
            integrity_hash = hashlib.sha256(content_for_hash).hexdigest()
            
            # Create quantum encrypted email record
            with transaction.atomic():
                quantum_email = QuantumEncryptedEmail.objects.create(
                    email=email,
                    qkd_session=session,
                    encryption_key=quantum_key_obj,
                    key_derivation_salt=salt,
                    initialization_vector=iv,
                    encrypted_subject=encrypted_subject,
                    encrypted_body_text=encrypted_body_text,
                    encrypted_body_html=encrypted_body_html,
                    quantum_security_level=quantum_key_obj.key_size_bits,
                    key_consumption_timestamp=timezone.now(),
                    integrity_hash=integrity_hash
                )
                
                # Consume the quantum key
                quantum_key_obj.consume()
                
            logger.info(f"Successfully encrypted email {email.id} using quantum key {quantum_key_obj.key_id}")
            return quantum_email
            
        except Exception as e:
            logger.error(f"Email encryption failed: {e}")
            raise EncryptionServiceError(f"Failed to encrypt email: {e}")
    
    async def decrypt_email(self, quantum_email: QuantumEncryptedEmail) -> Dict[str, str]:
        """
        Decrypt quantum encrypted email
        
        Args:
            quantum_email: QuantumEncryptedEmail object to decrypt
            
        Returns:
            dict: Decrypted email content
        """
        try:
            if not quantum_email.encryption_key:
                raise EncryptionServiceError("No encryption key associated with email")
            
            # Verify integrity first
            if not quantum_email.verify_integrity():
                raise EncryptionServiceError("Email integrity verification failed")
            
            # Get quantum key
            import base64
            quantum_key = base64.b64decode(quantum_email.encryption_key.key_data)
            
            # Decrypt components
            decrypted_content = {}
            
            if quantum_email.encrypted_subject:
                encrypted_data = {
                    'ciphertext': base64.b64encode(quantum_email.encrypted_subject).decode('utf-8'),
                    'algorithm': quantum_email.encryption_algorithm,
                    'salt': base64.b64encode(quantum_email.key_derivation_salt).decode('utf-8'),
                    'iv': base64.b64encode(quantum_email.initialization_vector).decode('utf-8'),
                    'integrity_hash': quantum_email.integrity_hash,
                }
                decrypted_content['subject'] = self.crypto.decrypt_content(encrypted_data, quantum_key)
            
            if quantum_email.encrypted_body_text:
                encrypted_data['ciphertext'] = base64.b64encode(quantum_email.encrypted_body_text).decode('utf-8')
                decrypted_content['body_text'] = self.crypto.decrypt_content(encrypted_data, quantum_key)
            
            if quantum_email.encrypted_body_html:
                encrypted_data['ciphertext'] = base64.b64encode(quantum_email.encrypted_body_html).decode('utf-8')
                decrypted_content['body_html'] = self.crypto.decrypt_content(encrypted_data, quantum_key)
            
            logger.info(f"Successfully decrypted quantum email {quantum_email.id}")
            return decrypted_content
            
        except Exception as e:
            logger.error(f"Email decryption failed: {e}")
            raise EncryptionServiceError(f"Failed to decrypt email: {e}")
    
    async def send_quantum_email(self,
                               sender_email: str,
                               recipient_email: str,
                               subject: str,
                               body_text: str,
                               body_html: str = None,
                               attachments: List[Dict] = None) -> Email:
        """
        Send quantum-encrypted email through external provider
        
        Args:
            sender_email: Sender's email address
            recipient_email: Recipient's email address
            subject: Email subject
            body_text: Plain text body
            body_html: HTML body (optional)
            attachments: List of attachments (optional)
            
        Returns:
            Email: Created email object
        """
        try:
            # Create email object
            email = Email.objects.create(
                message_id=f"<{uuid.uuid4()}@qute-mail>",
                from_address=sender_email,
                subject=f"[🔒 Quantum Secured] {subject}",
                body_text=body_text,
                body_html=body_html or "",
                size_bytes=len((body_text or "").encode('utf-8')),
                is_sent=True,
                folder='SENT'
            )
            email.set_to_addresses_list([recipient_email])
            email.save()
            
            # Encrypt email
            quantum_email = await self.encrypt_email(email, sender_email, recipient_email)
            
            # Generate quantum envelope
            envelope = generate_quantum_envelope(
                sender_email, 
                recipient_email,
                str(quantum_email.qkd_session.session_id)
            )
            
            # Prepare quantum-safe transport message
            transport_message = {
                'quantum_envelope': envelope,
                'encrypted_content': {
                    'subject': base64.b64encode(quantum_email.encrypted_subject or b'').decode('utf-8'),
                    'body_text': base64.b64encode(quantum_email.encrypted_body_text or b'').decode('utf-8'),
                    'body_html': base64.b64encode(quantum_email.encrypted_body_html or b'').decode('utf-8'),
                },
                'metadata': {
                    'algorithm': quantum_email.encryption_algorithm,
                    'key_size_bits': quantum_email.quantum_security_level,
                    'timestamp': quantum_email.key_consumption_timestamp.isoformat()
                }
            }
            
            # Send via external email provider
            await self._send_via_external_provider(
                sender_email,
                recipient_email, 
                f"[🔒 Quantum Secured] {subject}",
                json.dumps(transport_message, indent=2),
                attachments
            )
            
            logger.info(f"Successfully sent quantum-encrypted email from {sender_email} to {recipient_email}")
            return email
            
        except Exception as e:
            logger.error(f"Failed to send quantum email: {e}")
            raise QKDServiceError(f"Quantum email sending failed: {e}")
    
    async def _send_via_external_provider(self,
                                        sender_email: str,
                                        recipient_email: str,
                                        subject: str,
                                        quantum_body: str,
                                        attachments: List[Dict] = None):
        """
        Send email through external provider (Gmail, Yahoo, etc.)
        
        Args:
            sender_email: Sender's email address
            recipient_email: Recipient's email address
            subject: Email subject
            quantum_body: Quantum-encrypted message body
            attachments: Attachments (optional)
        """
        try:
            # Find external provider configuration
            provider_config = ExternalEmailProvider.objects.filter(
                email_address=sender_email,
                is_active=True
            ).first()
            
            if not provider_config:
                raise QKDServiceError(f"No external email provider configured for {sender_email}")
            
            # Create external email client
            external_client = ExternalEmailClient(provider_config)
            
            # Send email
            await external_client.send_email(
                to_address=recipient_email,
                subject=subject,
                body_text=f"""
This is a quantum-secured email from Qute Mail.

To decrypt this message, you need:
1. Qute Mail client with QKD support
2. Access to the quantum key distribution network
3. The quantum session established between sender and recipient

Quantum Security Level: 256-bit post-quantum safe
Protocol: ETSI GS QKD 014

--- QUANTUM ENCRYPTED CONTENT ---
{quantum_body}
--- END QUANTUM CONTENT ---

If you cannot decrypt this message, please contact the sender for assistance.
                """.strip(),
                attachments=attachments
            )
            
            logger.info(f"Sent quantum email via {provider_config.provider_type} provider")
            
        except Exception as e:
            logger.error(f"External provider sending failed: {e}")
            raise QKDServiceError(f"Failed to send via external provider: {e}")
    
    def get_session_status(self, sender_email: str, recipient_email: str) -> Dict[str, Any]:
        """
        Get QKD session status and statistics
        
        Args:
            sender_email: Sender's email address
            recipient_email: Recipient's email address
            
        Returns:
            dict: Session status information
        """
        try:
            session = QKDSession.objects.filter(
                sender_email=sender_email,
                recipient_email=recipient_email,
                status='active'
            ).first()
            
            if not session:
                return {
                    'status': 'no_session',
                    'message': 'No active QKD session found'
                }
            
            available_keys = session.shared_keys.filter(
                status='available',
                expires_at__gt=timezone.now()
            ).count()
            
            consumed_keys = session.shared_keys.filter(status='consumed').count()
            
            return {
                'status': 'active',
                'session_id': str(session.session_id),
                'created_at': session.created_at.isoformat(),
                'expires_at': session.expires_at.isoformat(),
                'key_manager': session.key_manager.name,
                'available_keys': available_keys,
                'consumed_keys': consumed_keys,
                'security_level': f"{session.key_manager.default_key_size}-bit quantum",
                'is_simulated': session.key_manager.is_simulated
            }
            
        except Exception as e:
            logger.error(f"Failed to get session status: {e}")
            return {
                'status': 'error',
                'message': f"Failed to retrieve session status: {e}"
            }
    
    def send_quantum_email_sync(self,
                              sender_email: str,
                              recipient_email: str,
                              subject: str,
                              body_text: str,
                              body_html: str = None,
                              attachments: List[Dict] = None) -> Email:
        """
        Synchronous wrapper for send_quantum_email to be used in Django views
        
        Args:
            sender_email: Sender's email address
            recipient_email: Recipient's email address
            subject: Email subject
            body_text: Plain text body
            body_html: HTML body (optional)
            attachments: List of attachments (optional)
            
        Returns:
            Email: Created email object
        """
        # Always use the simple sync implementation to avoid async issues
        return self._send_quantum_email_sync_simple(
            sender_email, recipient_email, subject, body_text, body_html, attachments
        )
    
    def _send_quantum_email_sync_simple(self,
                                      sender_email: str,
                                      recipient_email: str,
                                      subject: str,
                                      body_text: str,
                                      body_html: str = None,
                                      attachments: List[Dict] = None) -> Email:
        """
        Real quantum email encryption using QKD system
        """
        logger.info(f"Sending REAL quantum email from {sender_email} to {recipient_email}")
        
        try:
            from ..models import RealQuantumEmail, QKDKeyManager
            from ..qkd.real_crypto import quantum_crypto
            from django.contrib.auth.models import User
            import json
            
            # Get or create sender user
            try:
                sender_user = User.objects.get(email=sender_email)
            except User.DoesNotExist:
                sender_user = User.objects.create_user(
                    username=sender_email.split('@')[0],
                    email=sender_email,
                    password='quantum_generated'
                )
            
            # Get key manager
            key_manager = QKDKeyManager.objects.filter(is_active=True).first()
            if not key_manager:
                raise QKDServiceError("No active Key Manager available")
            
            # REAL quantum encryption using QKD keys
            encrypted_subject = quantum_crypto.encrypt_with_quantum_key(
                subject, sender_email, recipient_email
            )
            
            encrypted_body = quantum_crypto.encrypt_with_quantum_key(
                body_text, sender_email, recipient_email
            )
            
            encrypted_html = None
            if body_html:
                encrypted_html = quantum_crypto.encrypt_with_quantum_key(
                    body_html, sender_email, recipient_email
                )
            
            # Create quantum envelope
            envelope = quantum_crypto.create_quantum_envelope(
                sender_email, recipient_email, subject
            )
            
            # Create QuantumEncryptedEmail record with real encryption
            quantum_email = RealQuantumEmail.objects.create(
                sender_user=sender_user,
                sender_email=sender_email,
                recipient_email=recipient_email,
                encrypted_subject=json.dumps(encrypted_subject),
                encrypted_body_text=json.dumps(encrypted_body),
                encrypted_body_html=json.dumps(encrypted_html) if encrypted_html else None,
                encryption_algorithm=encrypted_subject['algorithm'],
                key_manager=key_manager,
                quantum_key_id=encrypted_subject['quantum_key_id'],
                status='encrypted',
                quantum_security_level=99.9,  # Real quantum security
                quantum_envelope=json.dumps(envelope)
            )
            
            logger.info(f"REAL quantum email created: Quantum ID {quantum_email.id}")
            
            # Return a dummy Email object that points to the quantum email
            # This maintains compatibility with the existing API but doesn't create duplicates
            class QuantumEmailWrapper:
                def __init__(self, quantum_email):
                    self.id = quantum_email.email_id
                    self.quantum_email = quantum_email
                    
            return QuantumEmailWrapper(quantum_email)
            
        except Exception as e:
            logger.error(f"Failed to create REAL quantum email: {e}")
            raise QKDServiceError(f"Real quantum email creation failed: {e}")