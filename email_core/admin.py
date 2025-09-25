from django.contrib import admin
from .models import EmailAccount, Email, EmailAttachment, Domain, AllowedDomain


@admin.register(AllowedDomain)
class AllowedDomainAdmin(admin.ModelAdmin):
    """Admin interface for AllowedDomain model"""
    list_display = ['domain_name', 'display_name', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['domain_name', 'display_name', 'description']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Domain Configuration', {
            'fields': ('domain_name', 'display_name', 'description', 'is_active')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    """Admin interface for EmailAccount model"""
    list_display = [
        'full_name', 'email_address', 'domain', 'allowed_domain', 'is_active', 'last_login', 'created_at'
    ]
    list_filter = ['is_active', 'allowed_domain', 'created_at', 'last_login']
    search_fields = ['full_name', 'email_address', 'domain__domain_name']
    readonly_fields = ['created_at', 'last_login']
    
    fieldsets = (
        ('User Information', {
            'fields': ('full_name', 'email_address', 'domain', 'allowed_domain')
        }),
        ('Account Settings', {
            'fields': ('quota_mb', 'is_active')
        }),
        ('Security', {
            'fields': ('password_hash',),
            'classes': ('collapse',)
        }),
        ('Activity', {
            'fields': ('last_login', 'created_at'),
            'classes': ('collapse',)
        }),
    )


class EmailAttachmentInline(admin.TabularInline):
    """Inline admin for attachments"""
    model = EmailAttachment
    extra = 0


@admin.register(Email)
class EmailAdmin(admin.ModelAdmin):
    """Admin interface for Email model"""
    list_display = [
        'subject', 'from_address', 'email_account', 'is_sent',
        'is_read', 'received_at'
    ]
    list_filter = ['is_sent', 'is_read', 'spf_pass', 'dkim_pass', 'dmarc_pass', 'received_at']
    search_fields = ['subject', 'from_address', 'to_addresses', 'message_id']
    readonly_fields = [
        'message_id', 'received_at', 'size_bytes', 'spf_pass', 'dkim_pass', 'dmarc_pass', 'spam_score'
    ]
    inlines = [EmailAttachmentInline]
    
    fieldsets = (
        ('Email Headers', {
            'fields': (
                'email_account', 'message_id', 'from_address', 'to_addresses', 'subject'
            )
        }),
        ('Content', {
            'fields': ('body_text', 'body_html', 'headers')
        }),
        ('Status & Security', {
            'fields': (
                'is_sent', 'is_read', 'folder', 'spf_pass', 'dkim_pass', 'dmarc_pass', 'spam_score'
            )
        }),
        ('Metadata', {
            'fields': ('size_bytes', 'received_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('email_account')


@admin.register(EmailAttachment)
class EmailAttachmentAdmin(admin.ModelAdmin):
    """Admin interface for EmailAttachment model"""
    list_display = ['filename', 'email', 'content_type', 'size_bytes']
    list_filter = ['content_type']
    search_fields = ['filename', 'email__subject']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('email')


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    """Admin interface for Domain model"""
    list_display = ['domain_name', 'user', 'is_verified', 'created_at']
    list_filter = ['is_verified', 'dmarc_policy', 'created_at']
    search_fields = ['domain_name', 'user__username']
    readonly_fields = ['created_at', 'updated_at', 'dkim_private_key', 'dkim_public_key']
    
    fieldsets = (
        ('Domain Information', {
            'fields': ('user', 'domain_name', 'is_verified', 'verification_token')
        }),
        ('DKIM Configuration', {
            'fields': ('dkim_selector', 'dkim_private_key', 'dkim_public_key'),
            'classes': ('collapse',)
        }),
        ('Security Policies', {
            'fields': ('spf_record', 'dmarc_policy')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
