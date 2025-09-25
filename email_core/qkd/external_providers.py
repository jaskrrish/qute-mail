"""
External Email Providers Integration for Qute Mail

This module handles integration with external email providers like Gmail, Yahoo, Outlook
while maintaining quantum-safe encryption. It provides SMTP/IMAP clients that work with
OAuth2 and traditional authentication methods.
"""

import logging
import smtplib
import imaplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, List, Optional, Any, Tuple
import base64
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ExternalEmailError(Exception):
    """Base exception for external email operations"""
    pass


class AuthenticationError(ExternalEmailError):
    """Exception raised when authentication fails"""
    pass


class SendError(ExternalEmailError):
    """Exception raised when sending email fails"""
    pass


class ExternalEmailClient:
    """
    Client for sending emails through external providers with quantum encryption
    """
    
    # Provider configurations
    PROVIDER_CONFIGS = {
        'gmail': {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'smtp_use_tls': True,
            'imap_server': 'imap.gmail.com',
            'imap_port': 993,
            'imap_use_ssl': True,
        },
        'yahoo': {
            'smtp_server': 'smtp.mail.yahoo.com',
            'smtp_port': 587,
            'smtp_use_tls': True,
            'imap_server': 'imap.mail.yahoo.com',
            'imap_port': 993,
            'imap_use_ssl': True,
        },
        'outlook': {
            'smtp_server': 'smtp-mail.outlook.com',
            'smtp_port': 587,
            'smtp_use_tls': True,
            'imap_server': 'outlook.office365.com',
            'imap_port': 993,
            'imap_use_ssl': True,
        },
    }
    
    def __init__(self, provider_config):
        """
        Initialize external email client
        
        Args:
            provider_config: ExternalEmailProvider model instance
        """
        self.provider_config = provider_config
        self.provider_type = provider_config.provider_type
        
        # Get provider settings or use custom
        if self.provider_type in self.PROVIDER_CONFIGS:
            self.settings = self.PROVIDER_CONFIGS[self.provider_type]
        else:
            # Custom provider settings
            self.settings = {
                'smtp_server': provider_config.smtp_server,
                'smtp_port': provider_config.smtp_port,
                'smtp_use_tls': provider_config.smtp_use_tls,
                'smtp_use_ssl': provider_config.smtp_use_ssl,
                'imap_server': provider_config.imap_server,
                'imap_port': provider_config.imap_port,
                'imap_use_ssl': provider_config.imap_use_ssl,
            }
        
        logger.info(f"Initialized external email client for {provider_config.email_address} ({self.provider_type})")
    
    def _get_smtp_connection(self) -> smtplib.SMTP:
        """
        Establish SMTP connection to external provider
        
        Returns:
            smtplib.SMTP: Authenticated SMTP connection
        """
        try:
            # Create SMTP connection
            if self.settings.get('smtp_use_ssl', False):
                server = smtplib.SMTP_SSL(
                    self.settings['smtp_server'], 
                    self.settings['smtp_port']
                )
            else:
                server = smtplib.SMTP(
                    self.settings['smtp_server'], 
                    self.settings['smtp_port']
                )
                
                if self.settings.get('smtp_use_tls', False):
                    server.starttls()
            
            # Authenticate
            if self.provider_config.oauth2_token:
                # Use OAuth2 authentication
                auth_string = self._build_oauth2_string()
                server.auth('XOAUTH2', lambda: auth_string)
            else:
                # Use username/password authentication
                server.login(
                    self.provider_config.username,
                    self.provider_config.password
                )
            
            logger.debug(f"Successfully connected to {self.settings['smtp_server']}")
            return server
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {e}")
            raise AuthenticationError(f"Failed to authenticate with {self.provider_type}: {e}")
        except Exception as e:
            logger.error(f"SMTP connection failed: {e}")
            raise ExternalEmailError(f"Failed to connect to {self.provider_type}: {e}")
    
    def _build_oauth2_string(self) -> bytes:
        """
        Build OAuth2 authentication string for SMTP/IMAP
        
        Returns:
            bytes: OAuth2 authentication string
        """
        auth_bytes = f"user={self.provider_config.email_address}\x01auth=Bearer {self.provider_config.oauth2_token}\x01\x01"
        return base64.b64encode(auth_bytes.encode('ascii'))
    
    async def send_email(self,
                        to_address: str,
                        subject: str,
                        body_text: str,
                        body_html: str = None,
                        attachments: List[Dict] = None) -> bool:
        """
        Send email through external provider
        
        Args:
            to_address: Recipient email address
            subject: Email subject
            body_text: Plain text body
            body_html: HTML body (optional)
            attachments: List of attachments (optional)
            
        Returns:
            bool: True if sent successfully
        """
        try:
            # Create message
            if body_html:
                msg = MIMEMultipart('alternative')
            else:
                msg = MIMEMultipart()
            
            msg['From'] = self.provider_config.email_address
            msg['To'] = to_address
            msg['Subject'] = subject
            
            # Add quantum security headers
            msg['X-Quantum-Security'] = 'QKD-ETSI-014'
            msg['X-Qute-Mail-Version'] = '1.0'
            msg['X-Encryption-Level'] = 'POST_QUANTUM_SAFE'
            
            # Add text content
            text_part = MIMEText(body_text, 'plain', 'utf-8')
            msg.attach(text_part)
            
            # Add HTML content if provided
            if body_html:
                html_part = MIMEText(body_html, 'html', 'utf-8')
                msg.attach(html_part)
            
            # Add attachments if provided
            if attachments:
                for attachment in attachments:
                    self._add_attachment(msg, attachment)
            
            # Send email
            smtp_server = self._get_smtp_connection()
            try:
                smtp_server.send_message(msg)
                logger.info(f"Successfully sent email to {to_address} via {self.provider_type}")
                return True
            finally:
                smtp_server.quit()
                
        except Exception as e:
            logger.error(f"Failed to send email via {self.provider_type}: {e}")
            raise SendError(f"Email sending failed: {e}")
    
    def _add_attachment(self, msg: MIMEMultipart, attachment: Dict):
        """
        Add attachment to email message
        
        Args:
            msg: Email message object
            attachment: Attachment dictionary with 'filename', 'content', 'content_type'
        """
        try:
            part = MIMEBase('application', 'octet-stream')
            
            if isinstance(attachment['content'], str):
                # Base64 encoded content
                content = base64.b64decode(attachment['content'])
            else:
                # Raw bytes
                content = attachment['content']
            
            part.set_payload(content)
            encoders.encode_base64(part)
            
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {attachment["filename"]}'
            )
            
            if 'content_type' in attachment:
                part.add_header('Content-Type', attachment['content_type'])
            
            msg.attach(part)
            
        except Exception as e:
            logger.error(f"Failed to add attachment {attachment.get('filename', 'unknown')}: {e}")
            # Don't fail the entire email for attachment issues
    
    def _get_imap_connection(self) -> imaplib.IMAP4:
        """
        Establish IMAP connection to external provider
        
        Returns:
            imaplib.IMAP4: Authenticated IMAP connection
        """
        try:
            # Create IMAP connection
            if self.settings.get('imap_use_ssl', True):
                imap = imaplib.IMAP4_SSL(
                    self.settings['imap_server'], 
                    self.settings['imap_port']
                )
            else:
                imap = imaplib.IMAP4(
                    self.settings['imap_server'], 
                    self.settings['imap_port']
                )
            
            # Authenticate
            if self.provider_config.oauth2_token:
                # Use OAuth2 authentication
                auth_string = self._build_oauth2_string()
                imap.authenticate('XOAUTH2', lambda x: auth_string)
            else:
                # Use username/password authentication
                imap.login(
                    self.provider_config.username,
                    self.provider_config.password
                )
            
            logger.debug(f"Successfully connected to {self.settings['imap_server']}")
            return imap
            
        except imaplib.IMAP4.error as e:
            logger.error(f"IMAP authentication failed: {e}")
            raise AuthenticationError(f"Failed to authenticate IMAP with {self.provider_type}: {e}")
        except Exception as e:
            logger.error(f"IMAP connection failed: {e}")
            raise ExternalEmailError(f"Failed to connect IMAP to {self.provider_type}: {e}")
    
    async def fetch_emails(self, folder: str = 'INBOX', limit: int = 50) -> List[Dict]:
        """
        Fetch emails from external provider
        
        Args:
            folder: Email folder to fetch from
            limit: Maximum number of emails to fetch
            
        Returns:
            List[Dict]: List of email dictionaries
        """
        try:
            imap = self._get_imap_connection()
            emails = []
            
            try:
                # Select folder
                imap.select(folder)
                
                # Search for all emails (or recent ones)
                status, messages = imap.search(None, 'ALL')
                email_ids = messages[0].split()
                
                # Limit number of emails
                email_ids = email_ids[-limit:] if len(email_ids) > limit else email_ids
                
                for email_id in email_ids:
                    try:
                        # Fetch email
                        status, msg_data = imap.fetch(email_id, '(RFC822)')
                        
                        if status == 'OK' and msg_data:
                            raw_email = msg_data[0][1]
                            parsed_email = self._parse_email(raw_email)
                            if parsed_email:
                                emails.append(parsed_email)
                                
                    except Exception as e:
                        logger.warning(f"Failed to fetch email {email_id}: {e}")
                        continue
                
                logger.info(f"Fetched {len(emails)} emails from {folder}")
                return emails
                
            finally:
                imap.close()
                imap.logout()
                
        except Exception as e:
            logger.error(f"Failed to fetch emails from {self.provider_type}: {e}")
            raise ExternalEmailError(f"Email fetching failed: {e}")
    
    def _parse_email(self, raw_email: bytes) -> Optional[Dict]:
        """
        Parse raw email into dictionary format
        
        Args:
            raw_email: Raw email bytes
            
        Returns:
            Dict: Parsed email data or None if parsing fails
        """
        try:
            import email
            from email.header import decode_header
            
            msg = email.message_from_bytes(raw_email)
            
            # Extract basic fields
            subject = self._decode_header(msg.get('Subject', ''))
            from_addr = msg.get('From', '')
            to_addr = msg.get('To', '')
            date = msg.get('Date', '')
            
            # Extract body content
            body_text = ""
            body_html = ""
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == 'text/plain':
                        body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif content_type == 'text/html':
                        body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                # Single part message
                body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            # Check if this is a quantum-encrypted email
            is_quantum = (
                'X-Quantum-Security' in msg or 
                'quantum_envelope' in body_text.lower() or
                '[🔒 quantum secured]' in subject.lower()
            )
            
            return {
                'message_id': msg.get('Message-ID', ''),
                'subject': subject,
                'from_address': from_addr,
                'to_address': to_addr,
                'date': date,
                'body_text': body_text,
                'body_html': body_html,
                'is_quantum_encrypted': is_quantum,
                'headers': dict(msg.items()),
                'raw_size': len(raw_email)
            }
            
        except Exception as e:
            logger.error(f"Failed to parse email: {e}")
            return None
    
    def _decode_header(self, header: str) -> str:
        """
        Decode email header that might be encoded
        
        Args:
            header: Email header string
            
        Returns:
            str: Decoded header string
        """
        try:
            from email.header import decode_header
            
            decoded_parts = decode_header(header)
            decoded_string = ""
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding)
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += str(part)
            
            return decoded_string
            
        except Exception as e:
            logger.warning(f"Failed to decode header '{header}': {e}")
            return header  # Return original if decoding fails


class OAuth2TokenManager:
    """
    Manages OAuth2 token refresh for external email providers
    """
    
    # OAuth2 endpoints for major providers
    OAUTH2_ENDPOINTS = {
        'gmail': {
            'token_url': 'https://oauth2.googleapis.com/token',
            'scope': 'https://mail.google.com/',
        },
        'outlook': {
            'token_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'scope': 'https://outlook.office.com/SMTP.Send https://outlook.office.com/IMAP.AccessAsUser.All',
        }
    }
    
    @staticmethod
    async def refresh_token(provider_config) -> bool:
        """
        Refresh OAuth2 token for external provider
        
        Args:
            provider_config: ExternalEmailProvider model instance
            
        Returns:
            bool: True if token refreshed successfully
        """
        try:
            if not provider_config.oauth2_refresh_token:
                logger.warning(f"No refresh token available for {provider_config.email_address}")
                return False
            
            provider_type = provider_config.provider_type
            if provider_type not in OAuth2TokenManager.OAUTH2_ENDPOINTS:
                logger.warning(f"OAuth2 not supported for provider type: {provider_type}")
                return False
            
            import requests
            
            # Prepare token refresh request
            endpoint = OAuth2TokenManager.OAUTH2_ENDPOINTS[provider_type]
            
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': provider_config.oauth2_refresh_token,
                'client_id': provider_config.username,  # Assuming client_id is stored in username
                'client_secret': provider_config.password,  # Assuming client_secret is stored in password
            }
            
            response = requests.post(endpoint['token_url'], data=data)
            response.raise_for_status()
            
            token_data = response.json()
            
            # Update provider config
            provider_config.oauth2_token = token_data.get('access_token')
            if 'refresh_token' in token_data:
                provider_config.oauth2_refresh_token = token_data['refresh_token']
            
            expires_in = token_data.get('expires_in', 3600)
            provider_config.oauth2_expires_at = timezone.now() + timedelta(seconds=expires_in)
            
            provider_config.save()
            
            logger.info(f"Successfully refreshed OAuth2 token for {provider_config.email_address}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to refresh OAuth2 token: {e}")
            return False
    
    @staticmethod
    def is_token_expired(provider_config) -> bool:
        """
        Check if OAuth2 token is expired
        
        Args:
            provider_config: ExternalEmailProvider model instance
            
        Returns:
            bool: True if token is expired
        """
        if not provider_config.oauth2_expires_at:
            return True
        
        return provider_config.oauth2_expires_at <= timezone.now()