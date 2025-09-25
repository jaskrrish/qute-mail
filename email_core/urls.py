from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    DomainViewSet, EmailAccountViewSet, EmailViewSet,
    email_login, email_register, email_logout, inbox, send_email, 
    get_email, mark_email_read, inbox_count,
    qkd_status, qkd_key_managers
)
from .qkd.views import (
    QKDKeyManagerViewSet, QKDSessionViewSet, ExternalEmailProviderViewSet,
    QuantumEmailAPIView
)

# Create a router and register our viewsets with it
router = DefaultRouter()
router.register(r'domains', DomainViewSet, basename='domain')
router.register(r'accounts', EmailAccountViewSet, basename='emailaccount')
router.register(r'emails', EmailViewSet, basename='email')

# QKD API endpoints
router.register(r'qkd/key-managers', QKDKeyManagerViewSet, basename='qkdkeymanager')
router.register(r'qkd/sessions', QKDSessionViewSet, basename='qkdsession')
router.register(r'qkd/providers', ExternalEmailProviderViewSet, basename='externalprovider')

# Email Client URLs with proper namespace
client_patterns = ([
    path('', email_login, name='login'),
    path('login/', email_login, name='login'),
    path('register/', email_register, name='register'),
    path('logout/', email_logout, name='logout'),
    path('inbox/', inbox, name='inbox'),
    path('send/', send_email, name='send_email'),
    path('email/<str:email_id>/', get_email, name='get_email'),
    path('email/<str:email_id>/read/', mark_email_read, name='mark_read'),
    path('api/inbox/count/', inbox_count, name='inbox_count'),
    # Public QKD status endpoints (no auth required)
    path('api/qkd/status/', qkd_status, name='qkd_status'),
    path('api/qkd/key-managers/', qkd_key_managers, name='qkd_key_managers'),
], 'email_client')

# QKD API URLs
qkd_patterns = ([
    path('send/', QuantumEmailAPIView.as_view(), name='send_quantum_email'),
    path('decrypt/', QuantumEmailAPIView.as_view(), name='decrypt_quantum_email'),
], 'qkd_api')

# The API URLs are now determined automatically by the router
urlpatterns = [
    path('api/', include(router.urls)),
    path('api/qkd/', include(qkd_patterns)),
    path('client/', include(client_patterns)),
]
