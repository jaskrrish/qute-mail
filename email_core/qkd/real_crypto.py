"""
Real Quantum Cryptography Service for Qute Mail

This module implements actual quantum-safe encryption using real quantum keys
from the QKD system. It replaces the demo implementation with proper
AES-256-GCM encryption using quantum-derived keys.
"""

import logging
import secrets
import base64
from typing import Tuple, Optional, Dict, Any
from datetime import datetime, timedelta
from django.utils import timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class QuantumCryptoError(Exception):
    """Base exception for quantum cryptography operations"""
    pass


class KeyNotAvailableError(QuantumCryptoError):
    """Raised when no quantum keys are available"""
    pass


class EncryptionError(QuantumCryptoError):
    """Raised when encryption fails"""
    pass


class DecryptionError(QuantumCryptoError):
    """Raised when decryption fails"""
    pass


class RealQuantumCrypto:
    """
    Real quantum cryptography implementation using QKD keys
    
    This class provides actual encryption/decryption using quantum keys
    retrieved from the QKD system, implementing AES-256-GCM with
    quantum-derived key material.
    """
    
    def __init__(self):
        self.algorithm = 'AES-256-GCM'
        self.key_size = 32  # 256 bits
        self.nonce_size = 12  # 96 bits for GCM
    
    def get_quantum_key(self, sender_email: str, recipient_email: str) -> 'QKDKey':
        """
        Get an available quantum key from the QKD system
        
        Args:
            sender_email: Sender's email address
            recipient_email: Recipient's email address
            
        Returns:
            QKDKey: Available quantum key
            
        Raises:
            KeyNotAvailableError: If no quantum keys are available
        """
        from ..models import QKDKey, QKDSession
        
        # First, try to find a key from an active session
        try:
            session = QKDSession.objects.filter(
                sender_email=sender_email,
                recipient_email=recipient_email,
                status='active',
                expires_at__gt=timezone.now()
            ).first()
            
            if session:
                available_key = session.shared_keys.filter(
                    status='available',
                    expires_at__gt=timezone.now()
                ).first()
                
                if available_key:
                    return available_key
        except Exception as e:
            logger.warning(f"Could not find session key: {e}")
        
        # Fall back to system keys (wildcard recipient)
        system_key = QKDKey.objects.filter(
            status='available',
            expires_at__gt=timezone.now(),
            recipient_email='*@*'
        ).first()
        
        if not system_key:
            raise KeyNotAvailableError("No quantum keys available for encryption")
        
        return system_key
    
    def derive_encryption_key(self, quantum_key: 'QKDKey', salt: bytes) -> bytes:
        """
        Derive an encryption key from quantum key material
        
        Args:
            quantum_key: QKD key object
            salt: Random salt for key derivation
            
        Returns:
            bytes: Derived encryption key
        """
        try:
            # Get the raw quantum key data
            if isinstance(quantum_key.key_data, str):
                # If stored as base64 string
                key_material = base64.b64decode(quantum_key.key_data.encode())
            else:
                # If stored as bytes
                key_material = bytes(quantum_key.key_data)
            
            # Use PBKDF2 to derive a strong encryption key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_size,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            derived_key = kdf.derive(key_material)
            return derived_key
            
        except Exception as e:
            raise EncryptionError(f"Failed to derive encryption key: {e}")
    
    def encrypt_with_quantum_key(self, plaintext: str, sender_email: str, recipient_email: str) -> Dict[str, Any]:
        """
        Encrypt plaintext using quantum-derived keys
        
        Args:
            plaintext: Text to encrypt
            sender_email: Sender's email address
            recipient_email: Recipient's email address
            
        Returns:
            dict: Encrypted data with metadata
            
        Raises:
            EncryptionError: If encryption fails
            KeyNotAvailableError: If no quantum keys available
        """
        try:
            # Get quantum key
            quantum_key = self.get_quantum_key(sender_email, recipient_email)
            
            # Generate random salt and nonce
            salt = secrets.token_bytes(16)  # 128 bits
            nonce = secrets.token_bytes(self.nonce_size)  # 96 bits
            
            # Derive encryption key from quantum key
            encryption_key = self.derive_encryption_key(quantum_key, salt)
            
            # Encrypt using AES-GCM
            aesgcm = AESGCM(encryption_key)
            ciphertext = aesgcm.encrypt(
                nonce, 
                plaintext.encode('utf-8'), 
                None  # No additional authenticated data
            )
            
            # Mark quantum key as consumed
            quantum_key.consume()
            
            # Prepare result
            encrypted_data = {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8'),
                'algorithm': self.algorithm,
                'quantum_key_id': str(quantum_key.key_id),
                'ksid': quantum_key.ksid,
                'key_size_bits': quantum_key.key_size_bits,
                'encrypted_at': timezone.now().isoformat()
            }
            
            logger.info(f"Successfully encrypted data using quantum key {quantum_key.key_id}")
            return encrypted_data
            
        except KeyNotAvailableError:
            raise
        except Exception as e:
            logger.error(f"Quantum encryption failed: {e}")
            raise EncryptionError(f"Quantum encryption failed: {e}")
    
    def decrypt_with_quantum_key(self, encrypted_data: Dict[str, Any], quantum_key: 'QKDKey') -> str:
        """
        Decrypt ciphertext using quantum-derived keys
        
        Args:
            encrypted_data: Dictionary with encrypted data and metadata
            quantum_key: QKD key used for encryption
            
        Returns:
            str: Decrypted plaintext
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            # Extract components
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            salt = base64.b64decode(encrypted_data['salt'])
            
            # Derive the same encryption key
            encryption_key = self.derive_encryption_key(quantum_key, salt)
            
            # Decrypt using AES-GCM
            aesgcm = AESGCM(encryption_key)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            
            plaintext = plaintext_bytes.decode('utf-8')
            
            logger.info(f"Successfully decrypted data using quantum key {quantum_key.key_id}")
            return plaintext
            
        except Exception as e:
            logger.error(f"Quantum decryption failed: {e}")
            raise DecryptionError(f"Quantum decryption failed: {e}")
    
    def create_quantum_envelope(self, sender_email: str, recipient_email: str, subject: str) -> Dict[str, Any]:
        """
        Create quantum security envelope with metadata
        
        Args:
            sender_email: Sender's email
            recipient_email: Recipient's email  
            subject: Email subject
            
        Returns:
            dict: Quantum envelope data
        """
        return {
            'version': '1.0',
            'protocol': 'QKD-ETSI-014',
            'sender': sender_email,
            'recipient': recipient_email,
            'subject_hint': subject[:50] + '...' if len(subject) > 50 else subject,
            'encryption_standard': self.algorithm,
            'created_at': timezone.now().isoformat(),
            'security_level': 'QUANTUM_SAFE',
            'key_distribution': 'QKD'
        }


# Global instance
quantum_crypto = RealQuantumCrypto()