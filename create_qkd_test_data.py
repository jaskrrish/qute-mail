#!/usr/bin/env python3
"""
Script to create initial QKD test data for Qute Mail
"""

import os
import sys
import django

# Add the project root to Python path
sys.path.insert(0, '/app')

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'email_service.settings')
django.setup()

from email_core.models import QKDKeyManager, ExternalEmailProvider, Domain, EmailAccount
from django.contrib.auth.models import User


def create_test_data():
    """Create initial test data for QKD system"""
    
    print("🔐 Creating QKD Key Manager...")
    
    # Create simulated Key Manager
    key_manager, created = QKDKeyManager.objects.get_or_create(
        name="Local QKD KM",
        defaults={
            'base_url': 'http://localhost:8080',
            'is_simulated': True,
            'is_active': True,
            'client_id': 'qute_mail_client',
            'client_secret': 'secret123',
            'default_key_size': 256,
            'max_key_lifetime': 3600,
        }
    )
    
    if created:
        print(f"✅ Created Key Manager: {key_manager.name}")
    else:
        print(f"ℹ️  Key Manager already exists: {key_manager.name}")
    
    print("\n📧 Creating External Email Providers...")
    
    # Get admin user for the providers
    admin_user = User.objects.get(username='admin')
    
    # Create Gmail provider
    gmail_provider, created = ExternalEmailProvider.objects.get_or_create(
        user=admin_user,
        email_address="test.quantum@gmail.com",
        defaults={
            'provider_type': 'gmail',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'smtp_use_ssl': False,
            'smtp_use_tls': True,
            'imap_server': 'imap.gmail.com',
            'imap_port': 993,
            'imap_use_ssl': True,
            'username': 'test.quantum@gmail.com',
            'password': 'app_password_here',  # App password for testing
            'qkd_enabled': True,
            'preferred_key_manager': key_manager,
            'is_active': True,
        }
    )
    
    if created:
        print(f"✅ Created Gmail provider: {gmail_provider.email_address}")
    else:
        print(f"ℹ️  Gmail provider already exists: {gmail_provider.email_address}")
    
    # Create Yahoo provider
    yahoo_provider, created = ExternalEmailProvider.objects.get_or_create(
        user=admin_user,
        email_address="quantum.test@yahoo.com",
        defaults={
            'provider_type': 'yahoo',
            'smtp_server': 'smtp.mail.yahoo.com',
            'smtp_port': 587,
            'smtp_use_ssl': False,
            'smtp_use_tls': True,
            'imap_server': 'imap.mail.yahoo.com',
            'imap_port': 993,
            'imap_use_ssl': True,
            'username': 'quantum.test@yahoo.com',
            'password': 'app_password_here',  # App password for testing
            'qkd_enabled': True,
            'preferred_key_manager': key_manager,
            'is_active': True,
        }
    )
    
    if created:
        print(f"✅ Created Yahoo provider: {yahoo_provider.email_address}")
    else:
        print(f"ℹ️  Yahoo provider already exists: {yahoo_provider.email_address}")
    
    print("\n🏢 Creating Domain and Email Account...")
    
    # Create domain
    domain, created = Domain.objects.get_or_create(
        domain_name="qute-mail.local",
        defaults={
            'user': admin_user,  # Domain also needs a user
        }
    )
    
    if created:
        print(f"✅ Created domain: {domain.domain_name}")
    else:
        print(f"ℹ️  Domain already exists: {domain.domain_name}")
    
    # Create email account
    email_account, created = EmailAccount.objects.get_or_create(
        email_address="quantum@qute-mail.local",
        defaults={
            'domain': domain,
            'password_hash': 'hashed_quantum123',  # In production, use proper hashing
            'is_active': True,
            'quota_mb': 2000,
        }
    )
    
    if created:
        print(f"✅ Created email account: {email_account.email_address}")
    else:
        print(f"ℹ️  Email account already exists: {email_account.email_address}")
    
    print(f"\n🎉 QKD Test Data Creation Complete!")
    print(f"📊 Summary:")
    print(f"   • Key Managers: {QKDKeyManager.objects.count()}")
    print(f"   • External Providers: {ExternalEmailProvider.objects.count()}")
    print(f"   • Domains: {Domain.objects.count()}")
    print(f"   • Email Accounts: {EmailAccount.objects.count()}")
    
    print(f"\n🔗 Access Links:")
    print(f"   • Admin Panel: http://localhost:8000/admin")
    print(f"   • Email Client: http://localhost:8000/client/")
    print(f"   • API Root: http://localhost:8000/api/")
    print(f"   • MailHog UI: http://localhost:8025")
    
    print(f"\n🔐 Login Details:")
    print(f"   • Admin User: admin / admin")
    print(f"   • Email Account: quantum@qute-mail.local / (see admin panel for password)")


if __name__ == '__main__':
    try:
        create_test_data()
    except Exception as e:
        print(f"❌ Error creating test data: {e}")
        sys.exit(1)