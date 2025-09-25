from django.core.management.base import BaseCommand
from email_core.models import Domain, EmailAccount
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = 'Create initial test data for the email service'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('🛠️  Creating initial test data...'))
        
        # Create a test domain
        try:
            domain, created = Domain.objects.get_or_create(
                domain_name='localhost',
                defaults={
                    'user': User.objects.get(is_superuser=True),  # Use the superuser you created
                    'is_verified': True,
                    'verification_token': 'test-token',
                    'spf_record': 'v=spf1 +all',
                    'dmarc_policy': 'none',
                    'dkim_selector': 'default',
                }
            )
            if created:
                self.stdout.write('  ✅ Created test domain: localhost')
            else:
                self.stdout.write('  ℹ️  Domain localhost already exists')
            
        except Exception as e:
            self.stdout.write(f'  ❌ Failed to create domain: {e}')
            return

        # Create test email accounts
        test_accounts = [
            ('admin@localhost', 'Administrator Account'),
            ('user@localhost', 'Test User Account'),
            ('noreply@localhost', 'No-Reply Account'),
        ]
        
        for email_addr, description in test_accounts:
            try:
                account, created = EmailAccount.objects.get_or_create(
                    email_address=email_addr,
                    defaults={
                        'domain': domain,
                        'password_hash': 'hashed_password_here',  # In real use, this would be properly hashed
                        'quota_mb': 1000,
                        'is_active': True,
                    }
                )
                if created:
                    self.stdout.write(f'  ✅ Created email account: {email_addr}')
                else:
                    self.stdout.write(f'  ℹ️  Email account {email_addr} already exists')
                    
            except Exception as e:
                self.stdout.write(f'  ❌ Failed to create email account {email_addr}: {e}')

        # Show summary
        self.stdout.write('\n📊 Current Data Summary:')
        domain_count = Domain.objects.count()
        account_count = EmailAccount.objects.count()
        self.stdout.write(f'  - Domains: {domain_count}')
        self.stdout.write(f'  - Email Accounts: {account_count}')
        
        self.stdout.write('\n🎯 Next Steps:')
        self.stdout.write('  1. Visit http://localhost:8000/admin/ to manage your email service')
        self.stdout.write('  2. Check http://localhost:8025 to see MailHog (email testing interface)')
        self.stdout.write('  3. Use the API endpoints at http://localhost:8000/api/')
        self.stdout.write('  4. Test email sending with: docker-compose exec web python manage.py test_email_service')
        
        self.stdout.write(self.style.SUCCESS('\n✨ Initial test data created successfully!'))