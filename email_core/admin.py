from django.contrib import admin
from .models import EmailAccount, Email, Attachment, EmailTemplate, EmailLog


@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    """Admin interface for EmailAccount model"""
    list_display = [
        'email_address', 'display_name', 'user', 'smtp_host',
        'smtp_port', 'is_active', 'created_at'
    ]
    list_filter = ['is_active', 'smtp_use_tls', 'created_at']
    search_fields = ['email_address', 'display_name', 'user__username']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('user', 'email_address', 'display_name', 'is_active')
        }),
        ('SMTP Settings', {
            'fields': (
                'smtp_host', 'smtp_port', 'smtp_use_tls',
                'smtp_username', 'smtp_password'
            )
        }),
        ('IMAP Settings', {
            'fields': ('imap_host', 'imap_port', 'imap_use_ssl')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


class AttachmentInline(admin.TabularInline):
    """Inline admin for attachments"""
    model = Attachment
    extra = 0
    readonly_fields = ['file_size', 'created_at']


@admin.register(Email)
class EmailAdmin(admin.ModelAdmin):
    """Admin interface for Email model"""
    list_display = [
        'subject', 'sender', 'recipient', 'status',
        'priority', 'created_at', 'sent_at'
    ]
    list_filter = ['status', 'priority', 'created_at', 'sent_at']
    search_fields = ['subject', 'sender', 'recipient', 'message_id']
    readonly_fields = [
        'message_id', 'created_at', 'sent_at',
        'error_message', 'retry_count'
    ]
    inlines = [AttachmentInline]
    
    fieldsets = (
        ('Email Headers', {
            'fields': (
                'account', 'message_id', 'sender', 'recipient',
                'cc', 'bcc', 'subject'
            )
        }),
        ('Content', {
            'fields': ('body_text', 'body_html')
        }),
        ('Status & Priority', {
            'fields': (
                'status', 'priority', 'scheduled_at',
                'error_message', 'retry_count', 'max_retries'
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'sent_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('account')


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    """Admin interface for Attachment model"""
    list_display = ['filename', 'email', 'content_type', 'file_size', 'created_at']
    list_filter = ['content_type', 'created_at']
    search_fields = ['filename', 'email__subject']
    readonly_fields = ['file_size', 'created_at']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('email')


@admin.register(EmailTemplate)
class EmailTemplateAdmin(admin.ModelAdmin):
    """Admin interface for EmailTemplate model"""
    list_display = ['name', 'subject_template', 'created_at', 'updated_at']
    search_fields = ['name', 'subject_template']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Template Information', {
            'fields': ('name', 'variables')
        }),
        ('Email Content', {
            'fields': (
                'subject_template', 'body_text_template', 'body_html_template'
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(EmailLog)
class EmailLogAdmin(admin.ModelAdmin):
    """Admin interface for EmailLog model"""
    list_display = ['email', 'level', 'message', 'created_at']
    list_filter = ['level', 'created_at']
    search_fields = ['message', 'email__subject']
    readonly_fields = ['created_at']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('email')
    
    def has_add_permission(self, request):
        # Logs should typically be created programmatically
        return False

from django.contrib import admin

# Register your models here.
