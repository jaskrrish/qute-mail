from django.core.management.base import BaseCommand
from email_core.models import QKDKey, RealQuantumEmail
from django.utils import timezone
from datetime import timedelta


class Command(BaseCommand):
    help = 'Check the status of quantum keys and clean up expired ones'

    def add_arguments(self, parser):
        parser.add_argument(
            '--cleanup',
            action='store_true',
            help='Remove expired and consumed keys'
        )
        parser.add_argument(
            '--detailed',
            action='store_true',
            help='Show detailed key information'
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('🔍 Quantum Key Status Report')
        )
        self.stdout.write('=' * 50)
        
        # Get key statistics
        total_keys = QKDKey.objects.count()
        available_keys = QKDKey.objects.filter(status='available').count()
        consumed_keys = QKDKey.objects.filter(status='consumed').count()
        expired_keys = QKDKey.objects.filter(expires_at__lt=timezone.now()).count()
        
        # Get quantum email statistics
        total_quantum_emails = RealQuantumEmail.objects.count()
        
        # Display summary
        self.stdout.write(f'📊 **Key Statistics:**')
        self.stdout.write(f'   Total Keys: {total_keys}')
        self.stdout.write(f'   Available: {available_keys} ✅')
        self.stdout.write(f'   Consumed: {consumed_keys} 🔴')
        self.stdout.write(f'   Expired: {expired_keys} ⏰')
        self.stdout.write('')
        
        self.stdout.write(f'📧 **Email Statistics:**')
        self.stdout.write(f'   Quantum Emails Sent: {total_quantum_emails}')
        self.stdout.write(f'   Estimated Emails Possible: ~{available_keys // 3}')
        self.stdout.write('')
        
        # Check key managers
        from email_core.models import QKDKeyManager
        key_managers = QKDKeyManager.objects.all()
        self.stdout.write(f'🌐 **Key Managers:**')
        for km in key_managers:
            km_keys = QKDKey.objects.filter(key_manager=km).count()
            km_available = QKDKey.objects.filter(
                key_manager=km,
                status='available'
            ).count()
            self.stdout.write(f'   {km.name}: {km_available}/{km_keys} available')
        
        # Show recent activity
        recent_consumed = QKDKey.objects.filter(
            status='consumed',
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        self.stdout.write('')
        self.stdout.write(f'📈 **Recent Activity (24h):**')
        self.stdout.write(f'   Keys consumed: {recent_consumed}')
        
        # Warnings
        if available_keys < 10:
            self.stdout.write(
                self.style.WARNING(f'\n⚠️  Warning: Only {available_keys} keys available!')
            )
            self.stdout.write('   Consider generating more keys with:')
            self.stdout.write('   python manage.py generate_quantum_keys --count 100')
        
        if expired_keys > 0:
            self.stdout.write(
                self.style.WARNING(f'\n⚠️  Warning: {expired_keys} expired keys found!')
            )
            self.stdout.write('   Clean them up with:')
            self.stdout.write('   python manage.py check_quantum_keys --cleanup')
        
        # Detailed view
        if options['detailed']:
            self.stdout.write('\n' + '=' * 50)
            self.stdout.write('🔍 **Detailed Key Information:**')
            
            recent_keys = QKDKey.objects.order_by('-created_at')[:10]
            for key in recent_keys:
                status_icon = '✅' if key.status == 'available' else '🔴' if key.status == 'consumed' else '⏰'
                self.stdout.write(
                    f'   {status_icon} {key.ksid[:20]}... | {key.status} | '
                    f'{key.created_at.strftime("%m-%d %H:%M")} | '
                    f'{key.key_size_bits}bit'
                )
        
        # Cleanup expired keys
        if options['cleanup']:
            self.stdout.write('\n' + '=' * 50)
            self.stdout.write('🧹 **Cleaning up expired and consumed keys...**')
            
            # Delete expired keys
            expired_deleted = QKDKey.objects.filter(expires_at__lt=timezone.now()).delete()
            
            # Delete old consumed keys (older than 7 days)
            old_consumed = QKDKey.objects.filter(
                status='consumed',
                created_at__lt=timezone.now() - timedelta(days=7)
            ).delete()
            
            self.stdout.write(f'   ✅ Deleted {expired_deleted[0]} expired keys')
            self.stdout.write(f'   ✅ Deleted {old_consumed[0]} old consumed keys')
            
            # Update statistics after cleanup
            new_total = QKDKey.objects.count()
            new_available = QKDKey.objects.filter(status='available').count()
            
            self.stdout.write(f'   📊 Remaining keys: {new_total} (Available: {new_available})')
        
        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(
            self.style.SUCCESS('✨ Quantum key status check complete!')
        )