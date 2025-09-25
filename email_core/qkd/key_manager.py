"""
ETSI GS QKD 014 Key Manager Client
Implements REST-based key delivery APIs for quantum key distribution

This module provides the interface to communicate with Key Managers (KM)
following the ETSI GS QKD 014 specification for quantum key distribution.
"""

import requests
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from django.utils import timezone
from django.conf import settings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import base64

logger = logging.getLogger(__name__)


class ETSIQKDError(Exception):
    """Base exception for QKD operations"""
    pass


class KeyManagerError(ETSIQKDError):
    """Exception raised when Key Manager operations fail"""
    pass


class KeyNotAvailableError(ETSIQKDError):
    """Exception raised when no quantum keys are available"""
    pass


class ETSIQKDClient:
    """
    Client for ETSI GS QKD 014 compliant Key Manager
    
    This class implements the REST API interface to communicate with
    Key Managers for quantum key retrieval and management.
    """
    
    def __init__(self, key_manager):
        """
        Initialize QKD client with Key Manager configuration
        
        Args:
            key_manager: QKDKeyManager model instance
        """
        self.key_manager = key_manager
        self.base_url = key_manager.base_url.rstrip('/')
        self.api_version = key_manager.api_version
        self.client_id = key_manager.client_id
        self.client_secret = key_manager.client_secret
        self.session = requests.Session()
        
        # Set default timeout
        self.timeout = getattr(settings, 'QKD_REQUEST_TIMEOUT', 30)
        
        # Configure session headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Qute-Mail-QKD-Client/1.0'
        })
    
    def _get_api_url(self, endpoint: str) -> str:
        """Construct full API URL"""
        return f"{self.base_url}/api/{self.api_version}/{endpoint}"
    
    async def authenticate(self) -> bool:
        """
        Authenticate with Key Manager using client credentials
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        try:
            auth_url = self._get_api_url('auth/token')
            
            auth_data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'key_delivery'
            }
            
            response = self.session.post(
                auth_url, 
                data=auth_data,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            token_data = response.json()
            access_token = token_data.get('access_token')
            expires_in = token_data.get('expires_in', 3600)
            
            if access_token:
                # Store token in Key Manager
                self.key_manager.access_token = access_token
                self.key_manager.token_expires_at = timezone.now() + timedelta(seconds=expires_in)
                self.key_manager.save()
                
                # Update session headers
                self.session.headers.update({
                    'Authorization': f'Bearer {access_token}'
                })
                
                logger.info(f"Successfully authenticated with Key Manager {self.key_manager.name}")
                return True
            
            return False
            
        except requests.RequestException as e:
            logger.error(f"Authentication failed for Key Manager {self.key_manager.name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during authentication: {e}")
            return False
    
    def _is_token_valid(self) -> bool:
        """Check if current access token is valid"""
        return (
            self.key_manager.access_token and
            self.key_manager.token_expires_at and
            self.key_manager.token_expires_at > timezone.now()
        )
    
    async def _ensure_authenticated(self) -> bool:
        """Ensure we have a valid authentication token"""
        if not self._is_token_valid():
            return await self.authenticate()
        else:
            # Update session headers with existing token
            self.session.headers.update({
                'Authorization': f'Bearer {self.key_manager.access_token}'
            })
            return True
    
    async def get_status(self) -> Dict:
        """
        Get Key Manager status according to ETSI GS QKD 014
        
        Returns:
            dict: Status information from Key Manager
        """
        if not await self._ensure_authenticated():
            raise KeyManagerError("Failed to authenticate with Key Manager")
        
        try:
            status_url = self._get_api_url('status')
            response = self.session.get(status_url, timeout=self.timeout)
            response.raise_for_status()
            
            return response.json()
            
        except requests.RequestException as e:
            logger.error(f"Failed to get Key Manager status: {e}")
            raise KeyManagerError(f"Status request failed: {e}")
    
    async def request_keys(self, 
                          ksid: str,
                          number: int = 1,
                          size: int = None,
                          additional_slave_SAE_IDs: List[str] = None) -> Dict:
        """
        Request quantum keys from Key Manager
        
        Args:
            ksid: Key Stream ID
            number: Number of keys to request
            size: Key size in bits (uses default if not specified)
            additional_slave_SAE_IDs: Additional Slave SAE IDs for multicast
            
        Returns:
            dict: Response from Key Manager containing keys
        """
        if not await self._ensure_authenticated():
            raise KeyManagerError("Failed to authenticate with Key Manager")
        
        try:
            keys_url = self._get_api_url('keys/' + ksid)
            
            request_data = {
                'number': number,
                'size': size or self.key_manager.default_key_size,
            }
            
            if additional_slave_SAE_IDs:
                request_data['additional_slave_SAE_IDs'] = additional_slave_SAE_IDs
            
            response = self.session.post(
                keys_url,
                json=request_data,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            keys_data = response.json()
            logger.info(f"Successfully retrieved {len(keys_data.get('keys', []))} keys from KSID {ksid}")
            
            return keys_data
            
        except requests.RequestException as e:
            logger.error(f"Failed to request keys from KSID {ksid}: {e}")
            if e.response and e.response.status_code == 404:
                raise KeyNotAvailableError(f"No keys available for KSID {ksid}")
            raise KeyManagerError(f"Key request failed: {e}")
    
    async def get_key_with_key_IDs(self, 
                                   ksid: str,
                                   key_IDs: List[str]) -> Dict:
        """
        Retrieve specific keys by their IDs
        
        Args:
            ksid: Key Stream ID
            key_IDs: List of specific key IDs to retrieve
            
        Returns:
            dict: Response containing the requested keys
        """
        if not await self._ensure_authenticated():
            raise KeyManagerError("Failed to authenticate with Key Manager")
        
        try:
            keys_url = self._get_api_url(f'keys/{ksid}/dec_keys')
            
            request_data = {
                'key_IDs': key_IDs
            }
            
            response = self.session.post(
                keys_url,
                json=request_data,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve keys by ID from KSID {ksid}: {e}")
            raise KeyManagerError(f"Key retrieval by ID failed: {e}")


class SimulatedQKDKeyManager:
    """
    Simulated Key Manager for testing and development
    
    This class simulates a QKD Key Manager that complies with ETSI GS QKD 014
    for testing purposes when real quantum hardware is not available.
    """
    
    def __init__(self, key_manager):
        """Initialize simulated Key Manager"""
        self.key_manager = key_manager
        self.simulated_keys = {}  # In-memory key storage
        logger.info(f"Initialized simulated Key Manager: {key_manager.name}")
    
    def _generate_quantum_key(self, size_bits: int) -> bytes:
        """Generate a simulated quantum key"""
        # In real QKD, this would come from quantum channel
        # For simulation, we use cryptographically strong random
        return secrets.token_bytes(size_bits // 8)
    
    async def authenticate(self) -> bool:
        """Simulated authentication - always succeeds"""
        # Generate fake token
        fake_token = base64.b64encode(f"simulated_token_{uuid.uuid4()}".encode()).decode()
        
        self.key_manager.access_token = fake_token
        self.key_manager.token_expires_at = timezone.now() + timedelta(hours=1)
        self.key_manager.save()
        
        logger.info(f"Simulated authentication successful for {self.key_manager.name}")
        return True
    
    async def get_status(self) -> Dict:
        """Get simulated Key Manager status"""
        return {
            'source_KME_ID': f"SIM-KME-{self.key_manager.id}",
            'target_KME_ID': f"SIM-KME-TARGET",
            'master_SAE_ID': "qute-mail-sender",
            'slave_SAE_ID': "qute-mail-receiver",
            'key_size': self.key_manager.default_key_size,
            'stored_key_count': len(self.simulated_keys),
            'max_key_count': 10000,
            'max_key_per_request': 100,
            'max_key_size': 1024,
            'min_key_size': 128,
            'max_SAE_ID_count': 10,
            'status_extension': {
                'simulation_mode': True,
                'quantum_channel_status': 'active',
                'error_rate': 0.001,
                'key_generation_rate': 1000  # keys per second
            }
        }
    
    async def request_keys(self, 
                          ksid: str,
                          number: int = 1,
                          size: int = None,
                          additional_slave_SAE_IDs: List[str] = None) -> Dict:
        """Generate and return simulated quantum keys"""
        
        key_size = size or self.key_manager.default_key_size
        generated_keys = []
        
        for i in range(number):
            key_id = str(uuid.uuid4())
            key_data = self._generate_quantum_key(key_size)
            
            # Store key for potential future retrieval
            self.simulated_keys[key_id] = {
                'key': key_data,
                'ksid': ksid,
                'size': key_size,
                'generated_at': timezone.now()
            }
            
            generated_keys.append({
                'key_ID': key_id,
                'key': base64.b64encode(key_data).decode(),
                'key_size': key_size
            })
        
        response = {
            'keys': generated_keys,
            'ksid': ksid,
            'master_SAE_ID': 'qute-mail-sender',
            'slave_SAE_ID': 'qute-mail-receiver'
        }
        
        if additional_slave_SAE_IDs:
            response['additional_slave_SAE_IDs'] = additional_slave_SAE_IDs
        
        logger.info(f"Generated {number} simulated quantum keys for KSID {ksid}")
        return response
    
    async def get_key_with_key_IDs(self, 
                                   ksid: str,
                                   key_IDs: List[str]) -> Dict:
        """Retrieve specific simulated keys by ID"""
        retrieved_keys = []
        
        for key_id in key_IDs:
            if key_id in self.simulated_keys:
                key_info = self.simulated_keys[key_id]
                if key_info['ksid'] == ksid:
                    retrieved_keys.append({
                        'key_ID': key_id,
                        'key': base64.b64encode(key_info['key']).decode(),
                        'key_size': key_info['size']
                    })
        
        return {
            'keys': retrieved_keys,
            'ksid': ksid
        }


def get_qkd_client(key_manager) -> ETSIQKDClient:
    """
    Factory function to get appropriate QKD client
    
    Args:
        key_manager: QKDKeyManager model instance
        
    Returns:
        ETSIQKDClient or SimulatedQKDKeyManager
    """
    if key_manager.is_simulated:
        return SimulatedQKDKeyManager(key_manager)
    else:
        return ETSIQKDClient(key_manager)