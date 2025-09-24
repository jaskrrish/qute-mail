import dns.resolver
import dkim
import spf
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

class SecurityChecker:
    """Handle SPF, DKIM, and DMARC security checks"""
    
    async def check_spf(self, sender_email: str, sender_ip: str) -> bool:
        """Verify SPF record"""
        try:
            domain = sender_email.split('@')[1] if '@' in sender_email else sender_email
            
            # Query SPF record
            result = spf.check2(
                i=sender_ip,
                s=sender_email,
                h=domain
            )
            
            return result[0] == 'pass'
        except Exception as e:
            logger.error(f"SPF check failed: {e}")
            return False
    
    async def check_dkim(self, email_content: bytes) -> bool:
        """Verify DKIM signature"""
        try:
            # Verify DKIM signature
            result = dkim.verify(email_content)
            return result
        except Exception as e:
            logger.error(f"DKIM check failed: {e}")
            return False
    
    async def check_dmarc(self, sender_email: str, spf_pass: bool, dkim_pass: bool) -> bool:
        """Check DMARC policy"""
        try:
            domain = sender_email.split('@')[1] if '@' in sender_email else sender_email
            
            # Query DMARC record
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=DMARC1'):
                    # Parse DMARC policy
                    policy = 'none'
                    for tag in txt_record.split(';'):
                        if tag.strip().startswith('p='):
                            policy = tag.split('=')[1].strip()
                    
                    # Check alignment
                    if policy == 'none':
                        return True
                    elif policy == 'quarantine':
                        return spf_pass or dkim_pass
                    elif policy == 'reject':
                        return spf_pass and dkim_pass
                        
            return True  # No DMARC record found
            
        except dns.resolver.NXDOMAIN:
            logger.info(f"No DMARC record found for {sender_email}")
            return True
        except Exception as e:
            logger.error(f"DMARC check failed: {e}")
            return False

class DKIMSigner:
    """Sign outgoing emails with DKIM"""
    
    @staticmethod
    def sign_email(email_content: bytes, domain_name: str) -> bytes:
        """Sign email with DKIM"""
        from email_core.models import Domain
        
        try:
            domain = Domain.objects.get(domain_name=domain_name)
            
            # Sign the email
            signature = dkim.sign(
                message=email_content,
                selector=domain.dkim_selector.encode(),
                domain=domain_name.encode(),
                privkey=domain.dkim_private_key.encode(),
                canonicalize=(b'relaxed', b'relaxed')
            )
            
            # Add signature to email
            return signature + email_content
            
        except Domain.DoesNotExist:
            logger.error(f"Domain {domain_name} not found for DKIM signing")
            return email_content
        except Exception as e:
            logger.error(f"DKIM signing failed: {e}")
            return email_content