from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
import smtplib
from email.mime.text import MIMEText


class Command(BaseCommand):
    help = 'Test the email service functionality'

    def add_arguments(self, parser):
        parser.add_argument(
            '--to-email',
            type=str,
            default='test@localhost',
            help='Email address to send test email to'
        )
        parser.add_argument(
            '--from-email',
            type=str,
            default='noreply@localhost',
            help='Email address to send test email from'
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('🚀 Testing Qute-Mail Service...'))
        
        # Test 1: Django Email Configuration
        self.stdout.write('\n📧 Testing Django Email Configuration...')
        try:
            # Test Django's email backend
            from django.core.mail import get_connection
            connection = get_connection()
            connection.open()
            self.stdout.write('  ✅ Django email backend connection successful')
            connection.close()
        except Exception as e:
            self.stdout.write(f'  ❌ Django email backend failed: {e}')

        # Test 2: Send test email via Django
        self.stdout.write('\n📨 Sending test email via Django...')
        try:
            send_mail(
                'Qute-Mail Test Email',
                'Hello! This is a test email from your Qute-Mail service.',
                options['from_email'],
                [options['to_email']],
                fail_silently=False,
            )
            self.stdout.write(f'  ✅ Test email sent via Django from {options["from_email"]} to {options["to_email"]}')
        except Exception as e:
            self.stdout.write(f'  ❌ Django email sending failed: {e}')

        # Test 3: Direct SMTP connection
        self.stdout.write('\n🔌 Testing direct SMTP connection...')
        try:
            server = smtplib.SMTP('smtp', 1025)  # Use Docker service name
            server.noop()
            self.stdout.write('  ✅ Direct SMTP connection successful')
            
            # Send direct email
            msg = MIMEText('Direct SMTP test email from Qute-Mail service')
            msg['Subject'] = 'Direct SMTP Test'
            msg['From'] = options['from_email']
            msg['To'] = options['to_email']
            
            server.sendmail(options['from_email'], [options['to_email']], msg.as_string())
            self.stdout.write(f'  ✅ Direct SMTP email sent successfully')
            server.quit()
            
        except Exception as e:
            self.stdout.write(f'  ❌ Direct SMTP failed: {e}')

        # Test 4: Database connectivity
        self.stdout.write('\n🗄️  Testing database connectivity...')
        try:
            from email_core.models import Domain, EmailAccount
            domain_count = Domain.objects.count()
            account_count = EmailAccount.objects.count()
            self.stdout.write(f'  ✅ Database connected - {domain_count} domains, {account_count} accounts')
        except Exception as e:
            self.stdout.write(f'  ❌ Database test failed: {e}')

        # Summary
        self.stdout.write('\n📋 Test Summary:')
        self.stdout.write('- Django Admin: http://localhost:8000/admin/')
        self.stdout.write('- API Root: http://localhost:8000/api/')
        self.stdout.write('- MailHog Interface: http://localhost:8025')
        self.stdout.write('- Check MailHog to see captured emails!')
        
        self.stdout.write(self.style.SUCCESS('\n✨ Qute-Mail service test completed!'))