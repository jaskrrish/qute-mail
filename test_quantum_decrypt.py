#!/usr/bin/env python3
"""
Test script for quantum email decryption functionality
"""
import requests
import json

def test_quantum_email_decryption():
    base_url = "http://localhost:8000"
    
    # First, let's try to login programmatically
    session = requests.Session()
    
    # Get quantum email list first
    print("🔍 Testing quantum email access...")
    
    # Try to get one of our quantum emails directly (this should work with sessions)
    quantum_email_id = "e6dff3aa-95c1-4c43-a408-a4d4d77c2bcc"
    
    try:
        # Test without session first (should fail)
        response = session.get(f"{base_url}/client/email/{quantum_email_id}/")
        print(f"Response without session: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Quantum Email Decryption Success!")
            print(f"Subject: {data.get('subject', 'N/A')}")
            print(f"From: {data.get('from_address', 'N/A')}")
            print(f"Is Quantum: {data.get('is_quantum', False)}")
            if data.get('is_quantum'):
                print(f"Security Level: {data.get('quantum_security_level', 'N/A')}%")
                print(f"Encryption: {data.get('encryption_algorithm', 'N/A')}")
        else:
            print(f"❌ Access failed: {response.status_code}")
            print(response.text[:500] if response.text else "No response content")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_quantum_email_decryption()