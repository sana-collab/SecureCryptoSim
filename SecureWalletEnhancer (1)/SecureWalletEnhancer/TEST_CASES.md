# Crypto Wallet Security Test Cases

## Manual Security Testing Guide for CY4053 Assignment

This document provides 20+ comprehensive test cases to demonstrate all cybersecurity features implemented in the Crypto Wallet application. For each test, take screenshots to document the results.

---

## Authentication & Authorization Tests

### Test 1: Weak Password Detection
**Objective**: Verify password strength validation  
**Steps**:
1. Go to Register page
2. Enter username: "testuser1"
3. Try password: "weak" (< 8 characters)
4. Click Register

**Expected Result**: Error message "Password must be at least 8 characters long"

**Screenshot**: Capture error message

---

### Test 2: Missing Uppercase in Password
**Objective**: Verify password requires uppercase  
**Steps**:
1. Go to Register page
2. Enter username: "testuser2"
3. Try password: "password123!" (no uppercase)
4. Click Register

**Expected Result**: Error message "Password must contain at least one uppercase letter"

**Screenshot**: Capture error message

---

### Test 3: Missing Special Character in Password
**Objective**: Verify password requires special character  
**Steps**:
1. Go to Register page
2. Enter username: "testuser3"
3. Try password: "Password123" (no special char)
4. Click Register

**Expected Result**: Error message "Password must contain at least one special character"

**Screenshot**: Capture error message

---

### Test 4: Successful Registration with Strong Password
**Objective**: Verify strong password acceptance  
**Steps**:
1. Go to Register page
2. Enter username: "secureuser"
3. Enter email: "user@example.com"
4. Enter password: "SecurePass123!"
5. Click Register

**Expected Result**: Success message "Registration successful! Please log in."

**Screenshot**: Capture success message and redirect to login

---

### Test 5: Duplicate Username Prevention
**Objective**: Verify duplicate username rejection  
**Steps**:
1. Try to register with username "secureuser" again
2. Use any valid password

**Expected Result**: Error message "Username already exists. Please choose another."

**Screenshot**: Capture error message

---

### Test 6: Unauthorized Dashboard Access
**Objective**: Verify protected routes  
**Steps**:
1. Log out if logged in
2. Manually try to access: http://[your-url]/dashboard
3. Without logging in first

**Expected Result**: Redirect to login page with message "Please log in to access this page"

**Screenshot**: Capture redirect and error message

---

### Test 7: Session Expiry (5 Minutes)
**Objective**: Verify automatic logout  
**Steps**:
1. Log in successfully
2. Wait 5 minutes without activity
3. Try to access any page or refresh

**Expected Result**: Session expired message and redirect to login

**Screenshot**: Capture expiry message

**Note**: For testing purposes, you can temporarily reduce the timeout in main.py to 1 minute

---

### Test 8: Successful Login
**Objective**: Verify login functionality  
**Steps**:
1. Go to Login page
2. Enter valid username and password
3. Click Login

**Expected Result**: Redirect to dashboard with welcome message

**Screenshot**: Capture dashboard

---

## Input Validation & Injection Prevention Tests

### Test 9: SQL Injection in Login (OR 1=1)
**Objective**: Verify SQL injection prevention  
**Steps**:
1. Go to Login page
2. Username: `admin' OR '1'='1`
3. Password: `anything`
4. Click Login

**Expected Result**: Login fails, shows "Invalid credentials"

**Screenshot**: Capture failed login attempt

---

### Test 10: SQL Injection in Add Funds
**Objective**: Verify SQL injection prevention in transactions  
**Steps**:
1. Log in successfully
2. Go to Add Funds
3. Enter amount: `100' OR '1'='1`
4. Click Add Funds

**Expected Result**: Error "Invalid input detected. Possible security threat blocked."

**Screenshot**: Capture security block message

---

### Test 11: XSS Attack Prevention (Script Tag)
**Objective**: Verify XSS prevention  
**Steps**:
1. Log in successfully
2. Go to Profile page
3. Enter display name: `<script>alert('XSS')</script>`
4. Click Update Profile

**Expected Result**: Input sanitized or blocked with error message

**Screenshot**: Capture sanitized display name (should show &lt;script&gt; instead of executing)

---

### Test 12: XSS Attack in Username Registration
**Objective**: Verify XSS prevention in registration  
**Steps**:
1. Try to register with username: `<script>alert('hack')</script>`
2. Use valid password

**Expected Result**: Error message about invalid username

**Screenshot**: Capture error message

---

### Test 13: Non-Numeric Input in Add Funds
**Objective**: Verify numeric validation  
**Steps**:
1. Log in successfully
2. Go to Add Funds
3. Enter amount: "abc" or "test123"
4. Click Add Funds

**Expected Result**: Error "Invalid numeric input"

**Screenshot**: Capture error message

---

### Test 14: Negative Amount Rejection
**Objective**: Verify positive number validation  
**Steps**:
1. Log in successfully
2. Go to Add Funds
3. Enter amount: "-100"
4. Click Add Funds

**Expected Result**: Error "Amount must be greater than zero"

**Screenshot**: Capture error message

---

### Test 15: Zero Amount Rejection
**Objective**: Verify non-zero validation  
**Steps**:
1. Log in successfully
2. Go to Withdraw
3. Enter amount: "0"
4. Click Withdraw

**Expected Result**: Error "Amount must be greater than zero"

**Screenshot**: Capture error message

---

## Data Encryption & Hashing Tests

### Test 16: Password Hashing Verification
**Objective**: Verify passwords are hashed in database  
**Steps**:
1. Register a new user
2. Open wallet.db with SQLite browser or command line
3. Query: `SELECT username, password_hash FROM users;`
4. Check password_hash column

**Expected Result**: Password hash starts with "$2b$" (bcrypt format), not plain text

**Screenshot**: Capture database query result showing hashed password

**Note**: The encryption key is stored in `encryption.key` file and persists across app restarts, ensuring all encrypted data remains decryptable.

---

### Test 17: Balance Encryption Verification
**Objective**: Verify balance is encrypted in database  
**Steps**:
1. Log in and add funds (e.g., 500)
2. Open wallet.db
3. Query: `SELECT username, balance FROM users;`
4. Check balance column

**Expected Result**: Balance shows encrypted string (not "500"), looks like random characters

**Screenshot**: Capture database showing encrypted balance

---

### Test 18: Decrypt Balance Feature
**Objective**: Verify decrypt functionality  
**Steps**:
1. Log in successfully
2. Add some funds (e.g., 100 crypto)
3. On dashboard, click "Decrypt Balance" button
4. Observe balance display

**Expected Result**: Balance shows decrypted value for 5 seconds, then returns to "********"

**Screenshot**: Capture both hidden and decrypted states

---

### Test 19: Transaction Amount Encryption
**Objective**: Verify transaction encryption  
**Steps**:
1. Perform deposit and withdrawal
2. Open wallet.db
3. Query: `SELECT transaction_type, amount FROM transactions;`

**Expected Result**: Amount column shows encrypted values

**Screenshot**: Capture encrypted transaction data

---

## Audit Logging Tests

### Test 20: Login Activity Logging
**Objective**: Verify audit logging  
**Steps**:
1. Log in as a user
2. Open audit_log.txt file
3. Check for login entry

**Expected Result**: Log contains entry like "[2025-10-31 15:00:00] User: secureuser | Action: Logged in successfully"

**Screenshot**: Capture audit log showing login

---

### Test 21: Transaction Logging
**Objective**: Verify transaction logging  
**Steps**:
1. Add funds (e.g., 200)
2. Withdraw funds (e.g., 50)
3. Check audit_log.txt

**Expected Result**: Log shows both deposit and withdrawal with amounts

**Screenshot**: Capture audit log entries for transactions

---

### Test 22: Profile Update Logging
**Objective**: Verify profile change logging  
**Steps**:
1. Update profile information
2. Check audit_log.txt

**Expected Result**: Log shows "Updated profile information" entry

**Screenshot**: Capture log entry

---

## File Upload Validation Tests

### Test 23: Valid Image Upload (JPG/PNG)
**Objective**: Verify allowed file types  
**Steps**:
1. Go to Profile page
2. Upload a .jpg or .png image
3. Click Update Profile

**Expected Result**: Success message, image uploaded

**Screenshot**: Capture successful upload and profile with image

---

### Test 24: Invalid File Type Rejection
**Objective**: Verify file type validation  
**Steps**:
1. Go to Profile page
2. Try to upload a .exe, .pdf, or .txt file
3. Click Update Profile

**Expected Result**: Error "Invalid file type. Only JPG and PNG files are allowed."

**Screenshot**: Capture error message

---

### Test 25: Executable File Rejection
**Objective**: Verify dangerous file rejection  
**Steps**:
1. Rename any file to have .exe extension
2. Try to upload it as profile picture
3. Click Update Profile

**Expected Result**: Upload rejected with error message

**Screenshot**: Capture rejection

---

## Transaction & Balance Tests

### Test 26: Successful Funds Addition
**Objective**: Verify add funds functionality  
**Steps**:
1. Log in with initial balance 0
2. Add funds: 1000 crypto
3. Check dashboard

**Expected Result**: Success message, transaction appears in recent transactions

**Screenshot**: Capture transaction list showing deposit

---

### Test 27: Successful Withdrawal
**Objective**: Verify withdrawal functionality  
**Steps**:
1. Ensure balance > 0
2. Withdraw amount less than balance
3. Check dashboard

**Expected Result**: Success message, balance decreased, transaction logged

**Screenshot**: Capture withdrawal transaction

---

### Test 28: Insufficient Balance Handling
**Objective**: Verify balance check  
**Steps**:
1. Check current balance
2. Try to withdraw more than available balance
3. Click Withdraw

**Expected Result**: Error "Insufficient balance"

**Screenshot**: Capture error message

---

## Error Handling Tests

### Test 29: Generic Error Messages (No Stack Traces)
**Objective**: Verify secure error handling  
**Steps**:
1. Cause various errors (invalid inputs, etc.)
2. Check error messages displayed

**Expected Result**: User-friendly error messages only, no stack traces or internal errors exposed

**Screenshot**: Capture various error messages

---

### Test 30: Empty Field Validation
**Objective**: Verify required field validation  
**Steps**:
1. Try to login with empty username or password
2. Try to add funds with empty amount
3. Try to register with empty fields

**Expected Result**: HTML5 validation or error messages for required fields

**Screenshot**: Capture validation messages

---

## Session Management Tests

### Test 31: Logout Functionality
**Objective**: Verify logout clears session  
**Steps**:
1. Log in successfully
2. Click Logout
3. Try to access dashboard directly

**Expected Result**: Logged out message, redirect to login if accessing protected pages

**Screenshot**: Capture logout confirmation

---

### Test 32: Multiple Login Prevention
**Objective**: Verify session behavior  
**Steps**:
1. Log in on one browser
2. Check if previous session is maintained or replaced

**Expected Result**: Session management works correctly

**Screenshot**: Document behavior

---

## Dashboard & UI Tests

### Test 33: Dashboard Display
**Objective**: Verify dashboard shows all required information  
**Steps**:
1. Log in successfully
2. Observe dashboard

**Expected Result**: Shows encrypted balance, recent transactions, audit logs

**Screenshot**: Capture complete dashboard

---

### Test 34: Transaction History Display
**Objective**: Verify transaction list  
**Steps**:
1. Perform multiple deposits and withdrawals
2. Check dashboard transaction list

**Expected Result**: Shows last 10 transactions with type, amount, and timestamp

**Screenshot**: Capture transaction history

---

### Test 35: Audit Log Display on Dashboard
**Objective**: Verify audit log visibility  
**Steps**:
1. Perform various actions
2. Check dashboard audit log section

**Expected Result**: Shows recent 5 activity logs for the user

**Screenshot**: Capture audit log section

---

## Additional Security Tests

### Test 36: Case Sensitivity Test
**Objective**: Verify username case handling  
**Steps**:
1. Register user "TestUser"
2. Try to login with "testuser" (different case)

**Expected Result**: Document whether login succeeds or fails (depends on implementation)

**Screenshot**: Capture result

---

### Test 37: Special Characters in Profile
**Objective**: Verify sanitization  
**Steps**:
1. Try various special characters in email and display name
2. Check if properly sanitized

**Expected Result**: Malicious patterns blocked, safe characters allowed

**Screenshot**: Capture sanitization behavior

---

### Test 38: Browser Back Button After Logout
**Objective**: Verify session security  
**Steps**:
1. Log in
2. Navigate to dashboard
3. Log out
4. Click browser back button

**Expected Result**: Cannot access dashboard, redirected to login

**Screenshot**: Capture redirect behavior

---

### Test 39: Direct URL Access to Protected Pages
**Objective**: Verify all routes are protected  
**Steps**:
1. Without logging in, try to access:
   - /dashboard
   - /add_funds
   - /withdraw
   - /profile

**Expected Result**: All redirect to login page

**Screenshot**: Capture redirects

---

### Test 40: Maximum Amount Limit
**Objective**: Verify amount limits  
**Steps**:
1. Try to add funds: 10000000 (very large number)
2. Click Add Funds

**Expected Result**: Error "Amount exceeds maximum limit"

**Screenshot**: Capture error message

---

## Testing Summary Checklist

- [ ] All 40+ test cases completed
- [ ] Screenshots captured for each test
- [ ] Password hashing verified in database
- [ ] Data encryption verified in database
- [ ] SQL injection prevention confirmed
- [ ] XSS prevention confirmed
- [ ] Input validation working
- [ ] Session management working
- [ ] Audit logging functional
- [ ] File upload validation working
- [ ] Error handling appropriate
- [ ] All security features demonstrated

---

## Notes for Testing

1. **Database Access**: Use DB Browser for SQLite or command line to inspect wallet.db
2. **Audit Logs**: Check audit_log.txt file in project root
3. **Screenshots**: Take clear screenshots showing inputs and results
4. **Documentation**: Compile all screenshots into Test_Cases.docx
5. **Session Timeout**: Can temporarily reduce timeout for faster testing

## Security Features Demonstrated

✅ **Authentication**: bcrypt password hashing  
✅ **Authorization**: Protected routes with login required  
✅ **Input Validation**: SQL injection & XSS prevention  
✅ **Encryption**: Fernet symmetric encryption  
✅ **Session Security**: 5-minute auto-logout  
✅ **Logging**: Comprehensive audit trail  
✅ **Error Handling**: Generic error messages  
✅ **File Upload**: Extension validation  

---

**End of Test Cases Document**
