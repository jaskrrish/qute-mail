from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    DomainViewSet, EmailAccountViewSet, EmailViewSet
)

# Create a router and register our viewsets with it
router = DefaultRouter()
router.register(r'domains', DomainViewSet, basename='domain')
router.register(r'accounts', EmailAccountViewSet, basename='emailaccount')
router.register(r'emails', EmailViewSet, basename='email')

# The API URLs are now determined automatically by the router
urlpatterns = [
    path('', include(router.urls)),
]
