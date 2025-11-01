# Crypto Wallet Simulation - CY4053 Secure FinTech Application

## Overview
This is a Flask-based secure crypto wallet simulation that demonstrates comprehensive cybersecurity concepts for the CY4053 assignment. The application includes user authentication, encrypted data storage, input validation, audit logging, and session management.

## Project Purpose
Built as an educational demonstration of cybersecurity best practices in a FinTech application, this project showcases:
- Secure authentication with bcrypt password hashing
- Data encryption using Fernet symmetric encryption
- Input validation and sanitization (SQL injection & XSS prevention)
- Session management with automatic expiry
- Comprehensive audit logging
- Secure file upload validation

## Current State
Fully functional crypto wallet application with all security features implemented and ready for testing.

## Recent Changes
- **2025-11-01**: Peer-to-peer transaction system added
  - Created /transaction route with comprehensive security validation
  - Implemented peer-to-peer crypto transfer functionality
  - Added security.log for detailed transaction attempt logging
  - Created /history route for complete transaction history
  - Updated dashboard with transaction navigation
  - Database schema extended to support recipient tracking
  
- **2025-11-01**: Enhanced security features added
  - Added input length validation (max 50 characters) for username and password
  - Implemented login attempt lockout system (5 failed attempts, 1 minute lockout)
  - Added password confirmation field with backend validation
  - Implemented data modification protection with username verification
  
- **2025-10-31**: Initial implementation
  - Created Flask application with authentication system
  - Implemented bcrypt password hashing with strength validation
  - Added Fernet encryption for balances and transactions
  - Built dashboard with encrypted balance display
  - Created add/withdraw funds functionality with validation
  - Implemented profile management with file upload
  - Added 5-minute session expiry
  - Created comprehensive audit logging system
  - Built responsive UI with Bootstrap 5

## Project Architecture

### Backend (main.py)
- **Framework**: Flask 3.0.0
- **Security**: bcrypt 4.1.2, cryptography 41.0.7
- **Database**: SQLite (wallet.db)
- **Key Features**:
  - Password validation (min 8 chars, uppercase, lowercase, digit, special char)
  - Input sanitization (prevents SQL injection, XSS)
  - Session management with 5-minute expiry
  - Fernet encryption for sensitive data
  - Audit logging to text file

### Frontend
- **Templates**: Jinja2 HTML templates
- **Styling**: Bootstrap 5.3.0 + custom CSS
- **Icons**: Font Awesome 6.4.0
- **Pages**: login, register, dashboard, add_funds, withdraw, transaction, history, profile, error

### Database Schema
**users table**:
- id (PRIMARY KEY)
- username (UNIQUE)
- password_hash (bcrypt)
- email
- display_name
- balance (encrypted with Fernet)
- profile_picture
- created_at

**transactions table**:
- id (PRIMARY KEY)
- user_id (FOREIGN KEY)
- transaction_type (Deposit, Withdrawal, Transfer Sent, Transfer Received)
- amount (encrypted)
- recipient_id (FOREIGN KEY, nullable)
- recipient_username (nullable)
- timestamp

### Security Features
1. **Authentication**: bcrypt password hashing, session-based login
2. **Authorization**: Protected routes with login_required decorator
3. **Input Validation**: Regex-based sanitization, numeric validation, max 50 character length enforcement
4. **Encryption**: Fernet symmetric encryption for balances/transactions
5. **Session Security**: 5-minute auto-logout, session expiry checks
6. **Login Protection**: Failed attempt tracking with 5-attempt lockout (1 minute duration)
7. **Password Confirmation**: Dual password entry with matching validation during registration
8. **Data Modification Protection**: Username verification for transaction and balance modification requests
9. **Transaction Security**: Sender verification, recipient validation, self-transfer blocking, balance checks
10. **Security Logging**: Comprehensive security.log tracking all transaction attempts with results and reasons
11. **Audit Logging**: Complete audit trail of all user actions in audit_log.txt
12. **Error Handling**: Generic error messages, no stack trace exposure
13. **File Upload**: Extension validation (.jpg, .png only), secure filenames

## File Structure
```
/
├── main.py                 # Main Flask application
├── wallet.db              # SQLite database (auto-created)
├── audit_log.txt          # Activity logs (auto-created)
├── security.log           # Transaction security logs (auto-created)
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── profile.html
│   ├── add_funds.html
│   ├── withdraw.html
│   ├── transaction.html   # Peer-to-peer transfer
│   ├── history.html       # Transaction history
│   └── error.html
├── static/                # Static assets
│   └── style.css
└── uploads/               # Profile pictures (auto-created)
```

## Testing Scenarios
The application is designed to be tested for 30+ manual security scenarios:
1. Weak password rejection
2. SQL injection prevention (' OR 1=1 --)
3. XSS prevention (<script>alert('XSS')</script>)
4. Duplicate username prevention
5. Session expiry (5 minutes)
6. Unauthorized access to dashboard
7. Password hashing verification
8. Balance encryption verification
9. Non-numeric input rejection
10. Negative amount rejection
11. Insufficient balance handling
12. File upload validation (.exe rejection)
13. Invalid file type rejection
14. Audit log recording
15. Empty field validation
16. Special character sanitization
17. Logout functionality
18. Profile update validation
19. Error handling (no stack traces)
20. Decrypt balance functionality
21. **Input length validation (>50 characters for username/password)**
22. **Password confirmation mismatch detection**
23. **Login lockout after 5 failed attempts**
24. **Lockout release after 1 minute**
25. **Unauthorized data modification attempt protection**
26. **Peer-to-peer transaction with valid recipient**
27. **Transaction with non-existent recipient**
28. **Self-transfer blocking**
29. **Transaction security logging (security.log)**
30. **Transaction history viewing for sent and received transfers**

## Running the Application
The Flask app runs on port 5000 with host 0.0.0.0. Access via the webview.

## Environment Variables
- `SESSION_SECRET`: Used for Flask session security

## Security Notes
- All passwords are hashed with bcrypt before storage
- All balances and transaction amounts are encrypted with Fernet
- **Encryption Key**: Persistent Fernet key stored in `encryption.key` file (auto-generated on first run, persists across restarts)
- All user inputs are sanitized to prevent injection attacks
- Sessions automatically expire after 5 minutes of inactivity
- File uploads are validated for type and size (max 2MB)
- Comprehensive audit logging tracks all user activities

## Important Files
- `encryption.key` - Fernet encryption key (DO NOT DELETE - contains key for decrypting all balances/transactions)
- `wallet.db` - SQLite database (contains encrypted user data)
- `audit_log.txt` - Activity audit trail
- `uploads/` - User profile pictures
