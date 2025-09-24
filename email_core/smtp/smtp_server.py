import asyncio
import logging
import email
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as Server
from email.message import EmailMessage
from .smtp_handler import EmailHandler
from .security import SecurityChecker
import base64

logger = logging.getLogger(__name__)

class CustomSMTPServer:
    def __init__(self, hostname='0.0.0.0', port=25):
        self.hostname = hostname
        self.port = port
        self.handler = EmailHandler()
        self.controller = None
        
    async def start(self):
        """Start the SMTP server"""
        self.controller = Controller(
            self.handler,
            hostname=self.hostname,
            port=self.port,
            server_kwargs={'enable_SMTPUTF8': True}
        )
        self.controller.start()
        logger.info(f"SMTP Server started on {self.hostname}:{self.port}")
        
    def stop(self):
        """Stop the SMTP server"""
        if self.controller:
            self.controller.stop()
            logger.info("SMTP Server stopped")

class AuthenticatedSMTPServer(Server):
    """SMTP Server with authentication support"""
    
    async def smtp_AUTH(self, arg):
        """Handle AUTH command for SMTP authentication"""
        if not arg:
            await self.push('501 Syntax: AUTH <mechanism>')
            return
            
        mechanism = arg.split()[0].upper()
        
        if mechanism == 'PLAIN':
            await self.push('334 ')
            response = await self.readline()
            # Decode and verify credentials
            credentials = base64.b64decode(response).decode('utf-8').split('\x00')
            username = credentials[1] if len(credentials) > 1 else ''
            password = credentials[2] if len(credentials) > 2 else ''
            
            if self.authenticate_user(username, password):
                await self.push('235 2.7.0 Authentication successful')
                self.session.authenticated = True
                self.session.username = username
            else:
                await self.push('535 5.7.8 Authentication failed')
        else:
            await self.push('504 5.7.4 Unrecognized authentication type')
    
    def authenticate_user(self, username, password):
        """Authenticate user against database"""
        from email_core.models import EmailAccount
        from django.contrib.auth.hashers import check_password
        
        try:
            account = EmailAccount.objects.get(email_address=username)
            return check_password(password, account.password_hash)
        except EmailAccount.DoesNotExist:
            return False