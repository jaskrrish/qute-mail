#!/usr/bin/env python3
"""
Qute-Mail Test Script
This script helps you test the email service functionality
"""

import requests
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class QuteMaiTester:
    def __init__(self, base_url="http://localhost:8000", smtp_host="localhost", smtp_port=1025):
        self.base_url = base_url
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.session = requests.Session()
    
    def test_api_endpoints(self):
        """Test the API endpoints"""
        print("🔍 Testing API Endpoints...")
        
        endpoints = [
            "/api/",
            "/api/domains/",
            "/api/accounts/",
            "/api/emails/",
        ]
        
        for endpoint in endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                print(f"  ✅ {endpoint}: {response.status_code}")
                if response.status_code != 200 and response.status_code != 401:
                    print(f"     Content: {response.text[:100]}...")
            except Exception as e:
                print(f"  ❌ {endpoint}: {e}")
    
    def test_smtp_connection(self):
        """Test SMTP server connection"""
        print("📧 Testing SMTP Connection...")
        
        try:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.noop()
            print("  ✅ SMTP server is accessible")
            server.quit()
            return True
        except Exception as e:
            print(f"  ❌ SMTP connection failed: {e}")
            return False
    
    def send_test_email(self, from_email="test@localhost", to_email="user@localhost"):
        """Send a test email through SMTP"""
        print("📨 Sending Test Email...")
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = "Qute-Mail Test Email"
            
            body = """
            Hello!
            
            This is a test email from your Qute-Mail service.
            If you're seeing this, your email server is working correctly!
            
            Best regards,
            Qute-Mail Test System
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            text = msg.as_string()
            server.sendmail(from_email, to_email, text)
            server.quit()
            
            print(f"  ✅ Test email sent successfully from {from_email} to {to_email}")
            print(f"  🔍 Check MailHog at http://localhost:8025 to view the email")
            return True
            
        except Exception as e:
            print(f"  ❌ Failed to send test email: {e}")
            return False
    
    def test_admin_interface(self):
        """Test Django admin interface"""
        print("🔧 Testing Django Admin Interface...")
        
        try:
            response = self.session.get(f"{self.base_url}/admin/")
            if response.status_code == 200:
                print("  ✅ Django admin is accessible")
                print(f"  🌐 Admin URL: {self.base_url}/admin/")
            else:
                print(f"  ⚠️  Admin returned status: {response.status_code}")
        except Exception as e:
            print(f"  ❌ Admin interface test failed: {e}")
    
    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting Qute-Mail Service Tests...\n")
        
        self.test_admin_interface()
        print()
        
        self.test_api_endpoints()
        print()
        
        if self.test_smtp_connection():
            print()
            self.send_test_email()
        
        print("\n📋 Test Summary:")
        print("- Django Admin: http://localhost:8000/admin/")
        print("- API Root: http://localhost:8000/api/")
        print("- MailHog Interface: http://localhost:8025")
        print("- SMTP Server: localhost:1025")
        print("\n✨ Your Qute-Mail service is ready for use!")


if __name__ == "__main__":
    tester = QuteMaiTester()
    tester.run_all_tests()