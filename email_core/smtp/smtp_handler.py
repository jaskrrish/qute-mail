import asyncio
import json
import logging
from email import message_from_bytes
from datetime import datetime
from aiosmtpd.handlers import AsyncMessage
from .security import SecurityChecker

logger = logging.getLogger(__name__)

class EmailHandler(AsyncMessage):
    """Handle incoming and outgoing emails"""
    
    def __init__(self):
        super().__init__()
        self.security_checker = SecurityChecker()
        
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Handle RCPT TO command"""
        from email_core.models import EmailAccount, Domain
        
        # Check if recipient domain is hosted
        domain_name = address.split('@')[1] if '@' in address else None
        
        if not domain_name:
            return '550 Invalid recipient address'
            
        try:
            domain = Domain.objects.get(domain_name=domain_name, is_verified=True)
            account = EmailAccount.objects.get(email_address=address, is_active=True)
            envelope.rcpt_tos.append(address)
            return '250 OK'
        except (Domain.DoesNotExist, EmailAccount.DoesNotExist):
            return '550 User unknown'
    
    async def handle_DATA(self, server, session, envelope):
        """Process the email data"""
        from email_core.models import Email, EmailAccount, EmailAttachment
        
        try:
            # Parse email message
            message = message_from_bytes(envelope.content)
            
            # Security checks
            spf_result = await self.security_checker.check_spf(
                envelope.mail_from, 
                session.peer[0]
            )
            dkim_result = await self.security_checker.check_dkim(envelope.content)
            dmarc_result = await self.security_checker.check_dmarc(
                envelope.mail_from,
                spf_result,
                dkim_result
            )
            
            # Save email for each recipient
            for rcpt in envelope.rcpt_tos:
                try:
                    account = EmailAccount.objects.get(email_address=rcpt)
                    
                    # Create email record
                    email_obj = Email.objects.create(
                        email_account=account,
                        message_id=message.get('Message-ID', ''),
                        from_address=envelope.mail_from,
                        to_addresses=json.dumps(envelope.rcpt_tos),
                        subject=message.get('Subject', 'No Subject'),
                        body_text=self.get_text_content(message),
                        body_html=self.get_html_content(message),
                        headers=dict(message.items()),
                        size_bytes=len(envelope.content),
                        spf_pass=spf_result,
                        dkim_pass=dkim_result,
                        dmarc_pass=dmarc_result,
                        folder='INBOX'
                    )
                    
                    # Process attachments
                    await self.process_attachments(message, email_obj)
                    
                    logger.info(f"Email saved for {rcpt}: {email_obj.id}")
                    
                except EmailAccount.DoesNotExist:
                    logger.error(f"Account not found for {rcpt}")
                    
            return '250 Message accepted for delivery'
            
        except Exception as e:
            logger.error(f"Error processing email: {e}")
            return '451 Temporary failure'
    
    def get_text_content(self, message):
        """Extract text content from email"""
        for part in message.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_content()
        return ''
    
    def get_html_content(self, message):
        """Extract HTML content from email"""
        for part in message.walk():
            if part.get_content_type() == 'text/html':
                return part.get_content()
        return ''
    
    async def process_attachments(self, message, email_obj):
        """Process and save email attachments"""
        from email_core.models import EmailAttachment
        
        for part in message.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    content = part.get_payload(decode=True)
                    EmailAttachment.objects.create(
                        email=email_obj,
                        filename=filename,
                        content_type=part.get_content_type(),
                        size_bytes=len(content),
                        file_data=content
                    )