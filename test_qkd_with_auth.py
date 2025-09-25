#!/usr/bin/env python3
"""
Test QKD functionality with proper API authentication
"""

import requests
import json

# API Configuration
BASE_URL = "http://localhost:8000"
API_TOKEN = "d0f25a0a19ba0901b32e8dc0c3f4c03523b0d2b1"

headers = {
    "Authorization": f"Token {API_TOKEN}",
    "Content-Type": "application/json"
}

def test_qkd_endpoints():
    """Test all QKD-related API endpoints"""
    print("🔐 Testing QKD API Endpoints with Authentication...")
    print(f"🔑 Using API Token: {API_TOKEN[:20]}...")
    
    # Test 1: Check QKD Key Managers
    print("\n1️⃣ Testing QKD Key Managers:")
    try:
        response = requests.get(f"{BASE_URL}/api/qkd/key-managers/", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Found {len(data)} Key Managers")
            for km in data:
                print(f"      • {km['name']} ({km['base_url']}) - {'Active' if km['is_active'] else 'Inactive'}")
        else:
            print(f"   ❌ Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")
    
    # Test 2: Check QKD Sessions
    print("\n2️⃣ Testing QKD Sessions:")
    try:
        response = requests.get(f"{BASE_URL}/api/qkd/sessions/", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Found {len(data)} QKD Sessions")
            for session in data:
                print(f"      • {session['session_id']} - Status: {session.get('status', 'N/A')}")
        else:
            print(f"   ❌ Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")
    
    # Test 3: Check External Providers
    print("\n3️⃣ Testing External Email Providers:")
    try:
        response = requests.get(f"{BASE_URL}/api/qkd/providers/", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Found {len(data)} External Providers")
            for provider in data:
                print(f"      • {provider['email_address']} - QKD: {'✅' if provider.get('qkd_enabled') else '❌'}")
        else:
            print(f"   ❌ Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")
    
    # Test 4: Try sending a quantum email
    print("\n4️⃣ Testing Quantum Email Sending:")
    quantum_email_data = {
        "sender_email": "quantum@qute-mail.local",
        "recipient_email": "test@example.com",
        "subject": "🔒 Quantum Test Email",
        "body_text": "This is a test of quantum-secured email communication using QKD technology!"
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/qkd/send/",
            headers=headers,
            data=json.dumps(quantum_email_data)
        )
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Quantum email sent successfully!")
            print(f"      • Status: {data.get('status', 'N/A')}")
            print(f"      • Email ID: {data.get('email_id', 'N/A')}")
            print(f"      • Quantum Secured: {data.get('quantum_secured', 'N/A')}")
        else:
            print(f"   ❌ Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")
    
    # Test 5: Check general API accessibility
    print("\n5️⃣ Testing General API Access:")
    endpoints = [
        "/api/",
        "/api/domains/",
        "/api/accounts/",
        "/api/emails/"
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
            status_icon = "✅" if response.status_code == 200 else "❌"
            print(f"   {status_icon} {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"   ❌ {endpoint}: Exception - {e}")

def test_frontend_access():
    """Test frontend access (no auth needed)"""
    print("\n🌐 Testing Frontend Access:")
    frontend_urls = [
        "/",
        "/client/",
        "/admin/",
    ]
    
    for url in frontend_urls:
        try:
            response = requests.get(f"{BASE_URL}{url}")
            status_icon = "✅" if response.status_code in [200, 302] else "❌"
            print(f"   {status_icon} {url}: {response.status_code}")
        except Exception as e:
            print(f"   ❌ {url}: Exception - {e}")

if __name__ == "__main__":
    print("🚀 Qute Mail QKD API Testing Suite")
    print("=" * 50)
    
    test_qkd_endpoints()
    test_frontend_access()
    
    print("\n" + "=" * 50)
    print("🎉 QKD API Testing Complete!")
    print(f"🔗 Access Links:")
    print(f"   • Admin Panel: http://localhost:8000/admin")
    print(f"   • Email Client: http://localhost:8000/client/")
    print(f"   • MailHog UI: http://localhost:8025")
    print(f"   • API Documentation: http://localhost:8000/api/")