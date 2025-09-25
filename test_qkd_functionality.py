#!/usr/bin/env python3
"""
Test script for QKD functionality in Qute Mail
"""

import json
import requests
from requests.auth import HTTPBasicAuth

BASE_URL = "http://localhost:8000"

def test_qkd_api():
    """Test QKD API endpoints"""
    
    print("🧪 Testing QKD API Endpoints...")
    
    # Test getting Key Managers
    print("\n📡 Testing Key Managers endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/api/qkd/key-managers/")
        if response.status_code == 200:
            print(f"✅ Key Managers API: {len(response.json())} key managers found")
        else:
            print(f"⚠️ Key Managers API returned status {response.status_code}")
    except Exception as e:
        print(f"❌ Error testing Key Managers API: {e}")
    
    # Test getting QKD Sessions
    print("\n🔐 Testing QKD Sessions endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/api/qkd/sessions/")
        if response.status_code == 200:
            sessions = response.json()
            print(f"✅ QKD Sessions API: {len(sessions)} sessions found")
        else:
            print(f"⚠️ QKD Sessions API returned status {response.status_code}")
    except Exception as e:
        print(f"❌ Error testing QKD Sessions API: {e}")
    
    # Test getting External Providers
    print("\n📧 Testing External Providers endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/api/qkd/providers/")
        if response.status_code == 200:
            providers = response.json()
            print(f"✅ External Providers API: {len(providers)} providers found")
            for provider in providers[:2]:  # Show first 2
                print(f"   • {provider.get('email_address')} ({provider.get('provider_type')})")
        else:
            print(f"⚠️ External Providers API returned status {response.status_code}")
    except Exception as e:
        print(f"❌ Error testing External Providers API: {e}")

def test_quantum_email_sending():
    """Test quantum email sending"""
    
    print("\n🚀 Testing Quantum Email Sending...")
    
    # Sample quantum email
    quantum_email_data = {
        "sender_email": "test.quantum@gmail.com",
        "recipient_email": "quantum@qute-mail.local",
        "subject": "🔒 Quantum-Secured Test Email",
        "body_text": "This is a test email secured with Quantum Key Distribution (QKD) technology!\n\n✅ Quantum encryption: ACTIVE\n🔐 Security level: MAXIMUM\n📡 Key source: Simulated QKD Manager\n\nThis message is protected by the laws of quantum mechanics!"
    }
    
    try:
        # First try without authentication
        response = requests.post(
            f"{BASE_URL}/api/qkd/send/",
            json=quantum_email_data,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 201 or response.status_code == 200:
            result = response.json()
            print(f"✅ Quantum email sent successfully!")
            print(f"   📧 Email ID: {result.get('email_id', 'N/A')}")
            print(f"   🔒 Quantum secured: {result.get('quantum_secured', False)}")
            print(f"   📝 Message: {result.get('message', 'No message')}")
        else:
            print(f"⚠️ Quantum email sending failed with status {response.status_code}")
            try:
                error_detail = response.json()
                print(f"   Error: {error_detail}")
            except:
                print(f"   Raw response: {response.text}")
                
    except Exception as e:
        print(f"❌ Error testing quantum email sending: {e}")

def test_health_endpoints():
    """Test basic health endpoints"""
    
    print("\n🏥 Testing Health Endpoints...")
    
    # Test main page
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"✅ Main page: Status {response.status_code}")
    except Exception as e:
        print(f"❌ Main page error: {e}")
    
    # Test client page
    try:
        response = requests.get(f"{BASE_URL}/client/")
        print(f"✅ Client page: Status {response.status_code}")
    except Exception as e:
        print(f"❌ Client page error: {e}")
    
    # Test admin page
    try:
        response = requests.get(f"{BASE_URL}/admin/")
        print(f"✅ Admin page: Status {response.status_code}")
    except Exception as e:
        print(f"❌ Admin page error: {e}")

if __name__ == '__main__':
    print("🔬 Qute Mail QKD Testing Suite")
    print("=" * 50)
    
    test_health_endpoints()
    test_qkd_api()
    test_quantum_email_sending()
    
    print("\n" + "=" * 50)
    print("🎯 Testing Complete!")
    print("\n🔗 Next Steps:")
    print("   1. Visit http://localhost:8000/client/ to test the UI")
    print("   2. Visit http://localhost:8000/admin/ to manage QKD settings")
    print("   3. Visit http://localhost:8025 to check MailHog for received emails")
    print("   4. Test quantum email composition and sending through the web interface")