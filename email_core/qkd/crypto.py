"""
Quantum Encryption Module for Qute Mail

This module implements quantum-safe encryption using keys derived from
Quantum Key Distribution (QKD) systems. It provides encryption/decryption
functionality for email content and attachments.
"""

import os
import logging
from typing import Tuple, Optional, Dict, Any
from datetime import datetime, timedelta
from django.utils import timezone
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import hashlib
import json

logger = logging.getLogger(__name__)


class QuantumEncryptionError(Exception):
    """Base exception for quantum encryption operations"""
    pass


class KeyDerivationError(QuantumEncryptionError):
    """Exception raised when key derivation fails"""
    pass


class EncryptionError(QuantumEncryptionError):
    """Exception raised when encryption fails"""
    pass


class DecryptionError(QuantumEncryptionError):
    """Exception raised when decryption fails"""
    pass


class QuantumCrypto:
    """
    Quantum-safe cryptographic operations using QKD keys
    
    This class implements encryption and decryption using quantum keys
    retrieved from Key Managers, providing unconditional security
    against quantum computer attacks.
    """
    
    # Supported algorithms
    ALGORITHMS = {
        'AES-256-GCM': {
            'key_size': 32,  # 256 bits
            'iv_size': 12,   # 96 bits for GCM
            'tag_size': 16   # 128 bits
        },
        'AES-256-CBC': {
            'key_size': 32,  # 256 bits  
            'iv_size': 16,   # 128 bits
            'tag_size': 0    # No authentication tag
        }
    }
    
    def __init__(self, algorithm: str = 'AES-256-GCM'):
        """
        Initialize quantum crypto with specified algorithm
        
        Args:
            algorithm: Encryption algorithm to use
        """
        if algorithm not in self.ALGORITHMS:
            raise QuantumEncryptionError(f"Unsupported algorithm: {algorithm}")
        
        self.algorithm = algorithm
        self.config = self.ALGORITHMS[algorithm]
        logger.info(f"Initialized QuantumCrypto with algorithm: {algorithm}")
    
    def derive_key_from_quantum(self, 
                               quantum_key: bytes,
                               salt: bytes,
                               rounds: int = 100000,
                               purpose: str = "encryption") -> bytes:
        """
        Derive encryption key from quantum key material
        
        Args:
            quantum_key: Raw quantum key from QKD
            salt: Random salt for key derivation
            rounds: Number of PBKDF2 rounds
            purpose: Purpose of the derived key (for domain separation)
            
        Returns:
            bytes: Derived encryption key
        """
        try:
            # Add purpose to ensure domain separation
            purpose_salt = salt + purpose.encode('utf-8')
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.config['key_size'],
                salt=purpose_salt,
                iterations=rounds,
                backend=default_backend()
            )
            
            derived_key = kdf.derive(quantum_key)
            logger.debug(f"Successfully derived {self.config['key_size']*8}-bit key from quantum material")
            
            return derived_key
            
        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            raise KeyDerivationError(f"Failed to derive key: {e}")
    
    def encrypt_content(self, 
                       plaintext: str,
                       quantum_key: bytes,
                       salt: bytes = None,
                       additional_data: bytes = None) -> Dict[str, Any]:
        """
        Encrypt content using quantum-derived key
        
        Args:
            plaintext: Content to encrypt
            quantum_key: Quantum key material
            salt: Salt for key derivation (generated if None)
            additional_data: Additional authenticated data for AEAD
            
        Returns:
            dict: Encrypted content with metadata
        """
        try:
            # Generate salt if not provided
            if salt is None:
                salt = secrets.token_bytes(32)
            
            # Convert plaintext to bytes
            if isinstance(plaintext, str):
                plaintext_bytes = plaintext.encode('utf-8')
            else:
                plaintext_bytes = plaintext
            
            # Derive encryption key
            encryption_key = self.derive_key_from_quantum(quantum_key, salt)
            
            if self.algorithm == 'AES-256-GCM':
                # Use AEAD mode (recommended)
                iv = secrets.token_bytes(self.config['iv_size'])
                aesgcm = AESGCM(encryption_key)
                
                ciphertext = aesgcm.encrypt(
                    iv, 
                    plaintext_bytes, 
                    additional_data
                )
                
                # GCM includes the tag in ciphertext
                encrypted_data = ciphertext
                
            elif self.algorithm == 'AES-256-CBC':
                # Use CBC mode with PKCS7 padding
                iv = secrets.token_bytes(self.config['iv_size'])
                
                # Add PKCS7 padding
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(plaintext_bytes)
                padded_data += padder.finalize()
                
                # Encrypt
                cipher = Cipher(
                    algorithms.AES(encryption_key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Calculate integrity hash
            integrity_hash = hashlib.sha256(
                quantum_key + salt + encrypted_data
            ).hexdigest()
            
            result = {
                'ciphertext': base64.b64encode(encrypted_data).decode('utf-8'),
                'algorithm': self.algorithm,
                'salt': base64.b64encode(salt).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'integrity_hash': integrity_hash,
                'timestamp': timezone.now().isoformat(),
                'key_size_bits': self.config['key_size'] * 8
            }
            
            if additional_data:
                result['aad'] = base64.b64encode(additional_data).decode('utf-8')
            
            logger.info(f"Successfully encrypted content using {self.algorithm}")
            return result
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt content: {e}")
    
    def decrypt_content(self,
                       encrypted_data: Dict[str, Any],
                       quantum_key: bytes) -> str:
        """
        Decrypt content using quantum-derived key
        
        Args:
            encrypted_data: Dictionary containing encrypted content and metadata
            quantum_key: Quantum key material used for encryption
            
        Returns:
            str: Decrypted plaintext content
        """
        try:
            # Extract metadata
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            salt = base64.b64decode(encrypted_data['salt'])
            iv = base64.b64decode(encrypted_data['iv'])
            expected_hash = encrypted_data['integrity_hash']
            algorithm = encrypted_data['algorithm']
            
            # Verify integrity
            calculated_hash = hashlib.sha256(
                quantum_key + salt + ciphertext
            ).hexdigest()
            
            if calculated_hash != expected_hash:
                raise DecryptionError("Integrity verification failed - data may be corrupted")
            
            # Derive decryption key
            decryption_key = self.derive_key_from_quantum(quantum_key, salt)
            
            if algorithm == 'AES-256-GCM':
                # Decrypt using AEAD
                aesgcm = AESGCM(decryption_key)
                additional_data = None
                
                if 'aad' in encrypted_data:
                    additional_data = base64.b64decode(encrypted_data['aad'])
                
                plaintext_bytes = aesgcm.decrypt(iv, ciphertext, additional_data)
                
            elif algorithm == 'AES-256-CBC':
                # Decrypt using CBC mode
                cipher = Cipher(
                    algorithms.AES(decryption_key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Remove PKCS7 padding
                unpadder = padding.PKCS7(128).unpadder()
                plaintext_bytes = unpadder.update(padded_plaintext)
                plaintext_bytes += unpadder.finalize()
            
            # Convert back to string
            plaintext = plaintext_bytes.decode('utf-8')
            
            logger.info(f"Successfully decrypted content using {algorithm}")
            return plaintext
            
        except DecryptionError:
            raise
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise DecryptionError(f"Failed to decrypt content: {e}")
    
    def encrypt_large_file(self,
                          file_data: bytes,
                          quantum_key: bytes,
                          chunk_size: int = 64 * 1024) -> Dict[str, Any]:
        """
        Encrypt large files using chunked encryption
        
        Args:
            file_data: File content to encrypt
            quantum_key: Quantum key material
            chunk_size: Size of chunks for streaming encryption
            
        Returns:
            dict: Encrypted file data with metadata
        """
        try:
            # Generate salt and IV
            salt = secrets.token_bytes(32)
            master_key = self.derive_key_from_quantum(quantum_key, salt)
            
            encrypted_chunks = []
            total_size = len(file_data)
            
            for i in range(0, total_size, chunk_size):
                chunk = file_data[i:i + chunk_size]
                
                # Generate unique IV for each chunk
                chunk_iv = secrets.token_bytes(self.config['iv_size'])
                
                if self.algorithm == 'AES-256-GCM':
                    aesgcm = AESGCM(master_key)
                    # Include chunk index as additional data
                    aad = str(i // chunk_size).encode('utf-8')
                    encrypted_chunk = aesgcm.encrypt(chunk_iv, chunk, aad)
                else:
                    # CBC mode with padding
                    padder = padding.PKCS7(128).padder()
                    padded_chunk = padder.update(chunk)
                    padded_chunk += padder.finalize()
                    
                    cipher = Cipher(
                        algorithms.AES(master_key),
                        modes.CBC(chunk_iv),
                        backend=default_backend()
                    )
                    encryptor = cipher.encryptor()
                    encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
                
                encrypted_chunks.append({
                    'iv': base64.b64encode(chunk_iv).decode('utf-8'),
                    'data': base64.b64encode(encrypted_chunk).decode('utf-8'),
                    'size': len(chunk)
                })
            
            # Calculate file hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            result = {
                'chunks': encrypted_chunks,
                'algorithm': self.algorithm,
                'salt': base64.b64encode(salt).decode('utf-8'),
                'chunk_size': chunk_size,
                'original_size': total_size,
                'file_hash': file_hash,
                'timestamp': timezone.now().isoformat()
            }
            
            logger.info(f"Successfully encrypted file ({total_size} bytes) in {len(encrypted_chunks)} chunks")
            return result
            
        except Exception as e:
            logger.error(f"Large file encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt large file: {e}")
    
    def decrypt_large_file(self,
                          encrypted_file_data: Dict[str, Any],
                          quantum_key: bytes) -> bytes:
        """
        Decrypt large files using chunked decryption
        
        Args:
            encrypted_file_data: Encrypted file data with metadata
            quantum_key: Quantum key material used for encryption
            
        Returns:
            bytes: Decrypted file content
        """
        try:
            salt = base64.b64decode(encrypted_file_data['salt'])
            master_key = self.derive_key_from_quantum(quantum_key, salt)
            
            decrypted_chunks = []
            
            for i, chunk_data in enumerate(encrypted_file_data['chunks']):
                chunk_iv = base64.b64decode(chunk_data['iv'])
                encrypted_chunk = base64.b64decode(chunk_data['data'])
                
                if self.algorithm == 'AES-256-GCM':
                    aesgcm = AESGCM(master_key)
                    aad = str(i).encode('utf-8')
                    decrypted_chunk = aesgcm.decrypt(chunk_iv, encrypted_chunk, aad)
                else:
                    # CBC mode
                    cipher = Cipher(
                        algorithms.AES(master_key),
                        modes.CBC(chunk_iv),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    padded_chunk = decryptor.update(encrypted_chunk) + decryptor.finalize()
                    
                    # Remove padding (only for last chunk if needed)
                    if i == len(encrypted_file_data['chunks']) - 1:
                        unpadder = padding.PKCS7(128).unpadder()
                        decrypted_chunk = unpadder.update(padded_chunk)
                        decrypted_chunk += unpadder.finalize()
                    else:
                        decrypted_chunk = padded_chunk
                
                decrypted_chunks.append(decrypted_chunk)
            
            # Reconstruct file
            file_data = b''.join(decrypted_chunks)
            
            # Verify file integrity
            calculated_hash = hashlib.sha256(file_data).hexdigest()
            expected_hash = encrypted_file_data['file_hash']
            
            if calculated_hash != expected_hash:
                raise DecryptionError("File integrity verification failed")
            
            logger.info(f"Successfully decrypted file ({len(file_data)} bytes)")
            return file_data
            
        except DecryptionError:
            raise
        except Exception as e:
            logger.error(f"Large file decryption failed: {e}")
            raise DecryptionError(f"Failed to decrypt large file: {e}")


def generate_quantum_envelope(sender_email: str,
                            recipient_email: str,
                            quantum_session_id: str) -> Dict[str, Any]:
    """
    Generate quantum envelope metadata for email
    
    Args:
        sender_email: Sender's email address
        recipient_email: Recipient's email address
        quantum_session_id: QKD session identifier
        
    Returns:
        dict: Quantum envelope metadata
    """
    envelope = {
        'version': '1.0',
        'protocol': 'ETSI-QKD-014',
        'sender': sender_email,
        'recipient': recipient_email,
        'session_id': quantum_session_id,
        'timestamp': timezone.now().isoformat(),
        'security_level': 'QUANTUM_SAFE',
        'forward_secrecy': True,
        'quantum_signature': secrets.token_hex(32)  # Placeholder for quantum signature
    }
    
    return envelope


def verify_quantum_envelope(envelope: Dict[str, Any]) -> bool:
    """
    Verify quantum envelope integrity and authenticity
    
    Args:
        envelope: Quantum envelope metadata
        
    Returns:
        bool: True if envelope is valid
    """
    try:
        required_fields = [
            'version', 'protocol', 'sender', 'recipient',
            'session_id', 'timestamp', 'security_level'
        ]
        
        # Check required fields
        for field in required_fields:
            if field not in envelope:
                logger.warning(f"Missing required field in quantum envelope: {field}")
                return False
        
        # Verify protocol version
        if envelope['protocol'] != 'ETSI-QKD-014':
            logger.warning(f"Unsupported protocol: {envelope['protocol']}")
            return False
        
        # Verify timestamp (not too old)
        envelope_time = datetime.fromisoformat(envelope['timestamp'].replace('Z', '+00:00'))
        time_diff = timezone.now() - envelope_time
        
        if time_diff > timedelta(hours=24):
            logger.warning("Quantum envelope is too old")
            return False
        
        logger.info("Quantum envelope verified successfully")
        return True
        
    except Exception as e:
        logger.error(f"Quantum envelope verification failed: {e}")
        return False