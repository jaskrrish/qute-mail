from django.core.management.base import BaseCommand
from email_core.models import QKDKey, QKDKeyManager
import secrets
import base64
import json
from datetime import datetime, timedelta
from django.utils import timezone


class Command(BaseCommand):
    help = 'Generate quantum keys for QKD encryption'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=50,
            help='Number of quantum keys to generate (default: 50)'
        )
        parser.add_argument(
            '--key-size',
            type=int,
            default=32,
            help='Size of each key in bytes (default: 32 bytes = 256 bits)'
        )
        parser.add_argument(
            '--key-manager',
            type=str,
            default='Local QKD KM',
            help='Key Manager name (default: Local QKD KM)'
        )
        parser.add_argument(
            '--expiry-hours',
            type=int,
            default=24,
            help='Key expiry time in hours (default: 24 hours)'
        )

    def handle(self, *args, **options):
        count = options['count']
        key_size = options['key_size']
        km_name = options['key_manager']
        expiry_hours = options['expiry_hours']
        
        self.stdout.write(
            self.style.SUCCESS(f'🔑 Generating {count} quantum keys...')
        )
        
        # Calculate expiry time
        expiry_time = timezone.now() + timedelta(hours=expiry_hours)
        
        # Get or create Key Manager
        from email_core.models import QKDKeyManager
        key_manager, created = QKDKeyManager.objects.get_or_create(
            name=km_name,
            defaults={
                'base_url': 'http://localhost:8080',
                'client_id': 'test_client',
                'client_secret': 'test_secret',
                'is_simulated': True
            }
        )
        
        if created:
            self.stdout.write(f'Created new Key Manager: {km_name}')
        
        keys_created = 0
        
        for i in range(count):
            try:
                # Generate cryptographically secure random key
                key_material = secrets.token_bytes(key_size)
                
                # Create unique KSID
                ksid = f"QK_{timezone.now().strftime('%Y%m%d_%H%M%S')}_{i:04d}"
                
                # Create QKD Key
                qkd_key = QKDKey.objects.create(
                    key_manager=key_manager,
                    ksid=ksid,
                    key_data=key_material,
                    key_size_bits=key_size * 8,
                    status='available',
                    expires_at=expiry_time,
                    sender_email='*@*',     # Wildcard for universal sender
                    recipient_email='*@*',  # Wildcard for universal recipient  
                    max_usage=1
                )
                
                keys_created += 1
                
                if keys_created % 10 == 0:
                    self.stdout.write(f'  ✓ Generated {keys_created}/{count} keys...')
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Failed to create key {i}: {str(e)}')
                )
        
        # Show summary
        total_keys = QKDKey.objects.count()
        available_keys = QKDKey.objects.filter(status='available').count()
        
        self.stdout.write(
            self.style.SUCCESS(f'\n🎉 Key Generation Complete!')
        )
        self.stdout.write(f'  📊 Created: {keys_created} new keys')
        self.stdout.write(f'  🔑 Total keys in database: {total_keys}')
        self.stdout.write(f'  ✅ Available keys: {available_keys}')
        self.stdout.write(f'  ⏰ Key expiry: {expiry_time.strftime("%Y-%m-%d %H:%M:%S")}')
        self.stdout.write(f'  🔒 Key size: {key_size * 8} bits')
        self.stdout.write(f'  🌐 Key Manager: {km_name}')
        
        # Show usage instructions
        self.stdout.write(
            self.style.WARNING('\n💡 Usage Instructions:')
        )
        self.stdout.write('  • Each quantum email uses 2-3 keys (subject, body, html)')
        self.stdout.write(f'  • With {available_keys} keys, you can send ~{available_keys // 3} quantum emails')
        self.stdout.write('  • Keys are consumed after use (quantum security)')
        self.stdout.write('  • Run this command again when you need more keys')
        
        # Show quick commands
        self.stdout.write(
            self.style.HTTP_INFO('\n🚀 Quick Commands:')
        )
        self.stdout.write('  Generate 100 keys: python manage.py generate_quantum_keys --count 100')
        self.stdout.write('  Generate 1-hour keys: python manage.py generate_quantum_keys --expiry-hours 1')
        self.stdout.write('  Check key status: python manage.py shell -c "from email_core.models import QKDKey; print(f\'Available: {QKDKey.objects.filter(status=\"available\").count()}\')"')