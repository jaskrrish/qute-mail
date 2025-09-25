# Multi-User Email Client Testing Guide

## 🎉 Your Email Client is Ready!

Your Qute-Mail service now has a complete multi-user email client! Here's how to test it with multiple users.

## 🔧 Access Points

### Main Email Client
- **URL:** http://localhost:8000 (redirects to login)
- **Login Page:** http://localhost:8000/client/login/
- **Admin Interface:** http://localhost:8000/admin/ (for management)
- **API Endpoints:** http://localhost:8000/api/ (for programmatic access)

## 👥 Test Accounts Available

- **alice@localhost** - Active account
- **bob@localhost** - Active account  
- **admin@localhost** - Active account
- **user@localhost** - Active account

**Password:** Any password works for demo purposes (authentication is simplified for testing)

## 🧪 Multi-User Testing Scenarios

### Scenario 1: Basic Email Exchange

1. **Open First Browser/Tab:**
   - Go to http://localhost:8000
   - Login as `alice@localhost` (any password)
   - You'll see the inbox interface

2. **Open Second Browser/Tab (or Incognito):**
   - Go to http://localhost:8000
   - Login as `bob@localhost` (any password)
   - You'll see Bob's empty inbox

3. **Send Email from Alice to Bob:**
   - In Alice's browser: Click "Compose" button
   - Fill out:
     - **To:** bob@localhost
     - **Subject:** Hello Bob!
     - **Message:** Hi Bob, this is Alice testing the email system!
   - Click "Send"

4. **Check Bob's Inbox:**
   - Switch to Bob's browser tab
   - Click "Refresh" or wait for auto-refresh (30 seconds)
   - You should see Alice's email appear

5. **Read the Email:**
   - Click on the email in Bob's inbox
   - The email will open in a modal
   - Click "Reply" to respond

### Scenario 2: Multi-User Conversation

1. **Continue from Scenario 1**
2. **Bob replies to Alice:**
   - Click "Reply" in the email modal
   - The compose form will pre-fill
   - Edit the message and send
3. **Alice receives the reply:**
   - Switch to Alice's tab
   - Refresh to see Bob's reply
4. **Multiple participants:**
   - Open third tab, login as `admin@localhost`
   - Send email to both Alice and Bob (note: current version sends to one recipient at a time)

### Scenario 3: Real-Time Features

1. **Auto-Refresh:** Emails are automatically checked every 30 seconds
2. **Toast Notifications:** Success/error messages appear as toast notifications
3. **Unread Indicators:** New emails show with a "New" badge
4. **Read Status:** Emails become less prominent once read

## ⚡ Key Features Implemented

### User Interface
- ✅ **Responsive Design** - Works on desktop and mobile
- ✅ **Bootstrap Styling** - Professional, clean interface
- ✅ **Modal Compose** - Compose emails without leaving the inbox
- ✅ **Email Reading** - Click emails to read in a modal
- ✅ **Reply Functionality** - Quick reply to emails

### User Authentication
- ✅ **Session-Based Login** - Secure session management
- ✅ **Per-User Inboxes** - Each user sees only their emails
- ✅ **Logout Functionality** - Clean session termination

### Email Management
- ✅ **Send Emails** - Compose and send emails between users
- ✅ **Inbox Display** - View received emails with sender, subject, preview
- ✅ **Read/Unread Status** - Visual indicators for new emails
- ✅ **Email Threading** - Reply functionality with context

### Real-Time Updates
- ✅ **Auto-Refresh** - Automatic inbox updates every 30 seconds
- ✅ **Manual Refresh** - Instant refresh button
- ✅ **Toast Notifications** - User feedback for all actions
- ✅ **Live Email Count** - Dynamic inbox count updates

### Technical Features
- ✅ **Database Storage** - All emails stored in PostgreSQL
- ✅ **JSON API** - REST endpoints for programmatic access
- ✅ **SMTP Integration** - Emails also sent to MailHog for testing
- ✅ **Error Handling** - Graceful error handling and user feedback

## 🎯 Testing Checklist

### Basic Functionality
- [ ] Can log in with different email accounts
- [ ] Can see personalized inbox for each user
- [ ] Can compose and send emails
- [ ] Can receive and read emails
- [ ] Can reply to emails
- [ ] Can logout and switch users

### Multi-User Features
- [ ] Emails sent between users appear in recipient's inbox
- [ ] Each user only sees their own emails
- [ ] Multiple users can be logged in simultaneously
- [ ] Real-time updates work across sessions

### User Experience
- [ ] Interface is responsive and intuitive
- [ ] Error messages are clear and helpful
- [ ] Loading states are visible
- [ ] Auto-refresh works reliably

## 🔍 Advanced Testing

### API Testing
```powershell
# Login programmatically (if needed for API access)
$headers = @{"Authorization" = "Token YOUR_API_TOKEN"}

# Check inbox via API
Invoke-WebRequest -Uri "http://localhost:8000/api/emails/" -Headers $headers
```

### Database Verification
```bash
# Check emails in database
docker-compose exec web python manage.py shell -c "
from email_core.models import Email
for email in Email.objects.all():
    print(f'{email.from_address} -> {email.get_to_addresses_list()}: {email.subject}')
"
```

### SMTP Testing
- Check MailHog interface at http://localhost:8025
- All sent emails should appear there for debugging

## 🐛 Troubleshooting

### Common Issues
1. **Login not working:** Check if email accounts exist in database
2. **Emails not appearing:** Check browser console for errors, verify user is logged in
3. **Send failures:** Verify recipient email exists
4. **Auto-refresh issues:** Check network connectivity and browser console

### Debug Information
- Browser Console: F12 -> Console tab
- Django Logs: `docker-compose logs web`
- Database State: Use Django admin at http://localhost:8000/admin/

## 🚀 Production Considerations

For production deployment, consider:
1. **Real Authentication:** Implement proper password verification
2. **Security:** Add CSRF protection, rate limiting
3. **Performance:** Add pagination, database indexing
4. **Real SMTP:** Replace MailHog with actual SMTP server
5. **SSL/HTTPS:** Enable secure connections
6. **Domain Management:** Add proper domain verification

## 📞 Support

The email client is fully functional for development and testing! You now have:

- Multiple users with separate inboxes
- Real-time email sending and receiving
- Professional email interface
- Both web UI and API access
- Complete email management system

Try opening multiple browser tabs with different users and send emails between them! 🎉