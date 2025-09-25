from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token


class Command(BaseCommand):
    help = 'Create API token for testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            help='Username to create token for (defaults to superuser)'
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('🔑 Creating API Token...'))
        
        try:
            if options['username']:
                user = User.objects.get(username=options['username'])
            else:
                user = User.objects.filter(is_superuser=True).first()
                
            if not user:
                self.stdout.write('❌ No user found')
                return
                
            token, created = Token.objects.get_or_create(user=user)
            
            if created:
                self.stdout.write(f'✅ Created new token for {user.username}')
            else:
                self.stdout.write(f'ℹ️  Using existing token for {user.username}')
                
            self.stdout.write(f'\n🔑 API Token: {token.key}')
            self.stdout.write('\n📝 Usage Examples:')
            self.stdout.write('  # Test API with authentication:')
            self.stdout.write('  curl -H "Authorization: Token ' + token.key + '" http://localhost:8000/api/domains/')
            self.stdout.write('')
            self.stdout.write('  # In PowerShell:')
            self.stdout.write('  $headers = @{"Authorization" = "Token ' + token.key + '"}')
            self.stdout.write('  Invoke-WebRequest -Uri "http://localhost:8000/api/domains/" -Headers $headers')
            
        except Exception as e:
            self.stdout.write(f'❌ Error: {e}')