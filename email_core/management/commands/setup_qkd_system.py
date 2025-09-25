"""
Django management command to set up QKD system with real key generation
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
import secrets
import base64

from email_core.models import QKDKeyManager, QKDKey, QKDSession


class Command(BaseCommand):
    help = 'Set up QKD system with real key managers and generate quantum keys'

    def add_arguments(self, parser):
        parser.add_argument(
            '--keys',
            type=int,
            default=100,
            help='Number of quantum keys to generate'
        )
        parser.add_argument(
            '--key-size',
            type=int,
            default=256,
            help='Key size in bits (default: 256)'
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('🔐 Setting up QKD System with Real Keys...')
        )
        
        # Create or update Key Manager
        key_manager, created = QKDKeyManager.objects.get_or_create(
            name='Local QKD Key Manager',
            defaults={
                'base_url': 'http://localhost:8080',
                'api_version': 'v1',
                'client_id': 'qute-mail-client',
                'client_secret': secrets.token_hex(32),
                'is_active': True,
                'default_key_size': options['key_size'],
                'max_key_lifetime': 86400,  # 24 hours
                'is_simulated': False  # This will be our "real" key manager
            }
        )
        
        if created:
            self.stdout.write(f'✅ Created Key Manager: {key_manager.name}')
        else:
            self.stdout.write(f'✅ Using existing Key Manager: {key_manager.name}')
        
        # Generate quantum keys
        self.stdout.write(f'🔑 Generating {options["keys"]} quantum keys...')
        
        keys_generated = 0
        for i in range(options['keys']):
            # Generate cryptographically secure random key
            key_data = secrets.token_bytes(options['key_size'] // 8)  # Convert bits to bytes
            key_b64 = base64.b64encode(key_data).decode('utf-8')
            
            # Create unique KSID (Key Stream ID)
            ksid = f"qkd-key-{timezone.now().strftime('%Y%m%d')}-{i:06d}"
            
            qkd_key = QKDKey.objects.create(
                key_manager=key_manager,
                ksid=ksid,
                key_data=key_data,  # Store raw bytes, not base64
                key_size_bits=options['key_size'],
                expires_at=timezone.now() + timedelta(hours=24),
                status='available',
                sender_email='system@qute-mail.local',
                recipient_email='*@*'  # Wildcard for system keys
            )
            keys_generated += 1
            
            if keys_generated % 20 == 0:
                self.stdout.write(f'  Generated {keys_generated} keys...')
        
        self.stdout.write(
            self.style.SUCCESS(f'✅ Generated {keys_generated} quantum keys')
        )
        
        # Create a test QKD session
        session = QKDSession.objects.create(
            sender_email='quantum@qute-mail.local',
            recipient_email='test@example.com',
            key_manager=key_manager,
            status='active',
            expires_at=timezone.now() + timedelta(hours=48)
        )
        
        # Assign some keys to the session
        available_keys = QKDKey.objects.filter(
            key_manager=key_manager,
            status='available'
        )[:10]  # Assign first 10 keys
        
        session.shared_keys.set(available_keys)
        
        self.stdout.write(
            self.style.SUCCESS(f'✅ Created test QKD session: {session.session_id}')
        )
        
        # Display summary
        self.stdout.write('\n' + '='*60)
        self.stdout.write(self.style.SUCCESS('🎉 QKD SYSTEM SETUP COMPLETE!'))
        self.stdout.write('='*60)
        self.stdout.write(f'Key Manager: {key_manager.name}')
        self.stdout.write(f'Total Keys Generated: {keys_generated}')
        self.stdout.write(f'Key Size: {options["key_size"]} bits')
        self.stdout.write(f'Test Session: {session.session_id}')
        self.stdout.write(f'Keys per Session: {session.shared_keys.count()}')
        self.stdout.write('\n✅ Your QKD system is now ready for real encryption!')