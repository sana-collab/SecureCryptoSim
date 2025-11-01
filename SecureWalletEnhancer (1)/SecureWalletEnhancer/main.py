import os
import re
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import bcrypt
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

failed_login_attempts = {}
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = timedelta(minutes=1)

def get_or_create_encryption_key():
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

encryption_key = get_or_create_encryption_key()
cipher_suite = Fernet(encryption_key)

def init_db():
    try:
        conn = sqlite3.connect('wallet.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                display_name TEXT,
                balance TEXT NOT NULL,
                profile_picture TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                amount TEXT NOT NULL,
                recipient_id INTEGER,
                recipient_username TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (recipient_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Database initialization error: {e}")
        return False

def log_activity(username, action):
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] User: {username} | Action: {action}\n"
        with open('audit_log.txt', 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Logging error: {e}")

def log_security(sender, receiver, amount, result, reason=""):
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] Sender: {sender} | Receiver: {receiver} | Amount: {amount} | Result: {result}"
        if reason:
            log_entry += f" | Reason: {reason}"
        log_entry += "\n"
        with open('security.log', 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Security logging error: {e}")

def encrypt_data(data):
    try:
        return cipher_suite.encrypt(str(data).encode()).decode()
    except Exception:
        return None

def decrypt_data(encrypted_data):
    try:
        return float(cipher_suite.decrypt(encrypted_data.encode()).decode())
    except Exception:
        return None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

def sanitize_input(user_input):
    if not user_input:
        return ""
    dangerous_patterns = [
        r'<script', r'javascript:', r'onerror', r'onload',
        r"'.*OR.*'", r'".*OR.*"', r'--', r';--', r'DROP TABLE',
        r'INSERT INTO', r'DELETE FROM', r'UPDATE.*SET', r'1=1'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, str(user_input), re.IGNORECASE):
            return None
    
    sanitized = str(user_input).replace('<', '&lt;').replace('>', '&gt;')
    return sanitized

def validate_numeric_input(value):
    try:
        num = float(value)
        if num <= 0:
            return False, "Amount must be greater than zero"
        if num > 1000000:
            return False, "Amount exceeds maximum limit"
        return True, num
    except (ValueError, TypeError):
        return False, "Invalid numeric input"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_session_expiry():
    if 'logged_in' in session:
        last_activity = session.get('last_activity')
        if last_activity:
            last_activity_time = datetime.fromisoformat(last_activity)
            if datetime.now() - last_activity_time > timedelta(minutes=5):
                return False
        session['last_activity'] = datetime.now().isoformat()
    return True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        
        if not check_session_expiry():
            username = session.get('username', 'Unknown')
            log_activity(username, 'Session expired - Auto logout')
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            email = request.form.get('email', '').strip()
            
            if len(username) > 50:
                flash('Input too long – maximum 50 characters.', 'error')
                return render_template('register.html')
            
            if len(password) > 50:
                flash('Input too long – maximum 50 characters.', 'error')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('register.html')
            
            username = sanitize_input(username)
            email = sanitize_input(email)
            
            if not username or username is None:
                flash('Invalid username. Please avoid special characters.', 'error')
                return render_template('register.html')
            
            if len(username) < 3:
                flash('Username must be at least 3 characters long', 'error')
                return render_template('register.html')
            
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'error')
                return render_template('register.html')
            
            conn = sqlite3.connect('wallet.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                flash('Username already exists. Please choose another.', 'error')
                conn.close()
                return render_template('register.html')
            
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            initial_balance = encrypt_data(0.0)
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, balance)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, email, initial_balance))
            
            conn.commit()
            conn.close()
            
            log_activity(username, 'User registered successfully')
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            if len(username) > 50:
                flash('Input too long – maximum 50 characters.', 'error')
                return render_template('login.html')
            
            if len(password) > 50:
                flash('Input too long – maximum 50 characters.', 'error')
                return render_template('login.html')
            
            username = sanitize_input(username)
            
            if not username or username is None:
                flash('Invalid credentials', 'error')
                return render_template('login.html')
            
            if username in failed_login_attempts:
                attempt_data = failed_login_attempts[username]
                if attempt_data['count'] >= LOCKOUT_THRESHOLD:
                    time_elapsed = datetime.now() - attempt_data['lockout_time']
                    if time_elapsed < LOCKOUT_DURATION:
                        flash('Account temporarily locked due to too many failed attempts.', 'error')
                        log_activity(username, 'Login attempt during lockout period')
                        return render_template('login.html')
                    else:
                        failed_login_attempts[username] = {'count': 0, 'lockout_time': None}
            
            conn = sqlite3.connect('wallet.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                if username in failed_login_attempts:
                    failed_login_attempts[username] = {'count': 0, 'lockout_time': None}
                
                session.permanent = True
                session['logged_in'] = True
                session['user_id'] = user[0]
                session['username'] = username
                session['last_activity'] = datetime.now().isoformat()
                
                log_activity(username, 'Logged in successfully')
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                if username not in failed_login_attempts:
                    failed_login_attempts[username] = {'count': 0, 'lockout_time': None}
                
                failed_login_attempts[username]['count'] += 1
                
                if failed_login_attempts[username]['count'] >= LOCKOUT_THRESHOLD:
                    failed_login_attempts[username]['lockout_time'] = datetime.now()
                    flash('Account temporarily locked due to too many failed attempts.', 'error')
                    log_activity(username, f'Account locked after {LOCKOUT_THRESHOLD} failed attempts')
                else:
                    flash('Invalid credentials', 'error')
                    log_activity(username if username else 'Unknown', 'Failed login attempt')
                
        except Exception as e:
            flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', 'Unknown')
    log_activity(username, 'Logged out')
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        
        conn = sqlite3.connect('wallet.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT balance, email, display_name, profile_picture FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        
        encrypted_balance = user_data[0]
        balance = "********"
        email = user_data[1] or "Not set"
        display_name = user_data[2] or username
        profile_picture = user_data[3]
        
        cursor.execute('''
            SELECT transaction_type, amount, timestamp 
            FROM transactions 
            WHERE user_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''', (user_id,))
        
        transactions = []
        for row in cursor.fetchall():
            trans_type = row[0]
            encrypted_amount = row[1]
            timestamp = row[2]
            
            decrypted_amount = decrypt_data(encrypted_amount)
            if decrypted_amount is not None:
                transactions.append({
                    'type': trans_type,
                    'amount': f"{decrypted_amount:.2f}",
                    'timestamp': timestamp
                })
        
        try:
            with open('audit_log.txt', 'r') as f:
                all_logs = f.readlines()
                user_logs = [log for log in all_logs if f"User: {username}" in log]
                recent_logs = user_logs[-5:]
        except FileNotFoundError:
            recent_logs = []
        
        conn.close()
        
        return render_template('dashboard.html', 
                             username=username,
                             display_name=display_name,
                             balance=balance,
                             encrypted_balance=encrypted_balance,
                             email=email,
                             transactions=transactions,
                             logs=recent_logs,
                             profile_picture=profile_picture)
        
    except Exception as e:
        flash('An error occurred while loading the dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/decrypt_balance', methods=['POST'])
@login_required
def decrypt_balance():
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        
        conn = sqlite3.connect('wallet.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
        encrypted_balance = cursor.fetchone()[0]
        conn.close()
        
        decrypted = decrypt_data(encrypted_balance)
        
        if decrypted is not None:
            log_activity(username, 'Decrypted balance view')
            return jsonify({'success': True, 'balance': f"{decrypted:.2f}"})
        else:
            return jsonify({'success': False, 'error': 'Decryption failed'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': 'An error occurred'})

@app.route('/add_funds', methods=['GET', 'POST'])
@login_required
def add_funds():
    if request.method == 'POST':
        try:
            user_id = session.get('user_id')
            username = session.get('username')
            
            request_user = request.form.get('username', '').strip()
            if request_user and request_user != username:
                flash('Unauthorized modification attempt.', 'error')
                log_activity(username, f'Unauthorized add funds attempt - User mismatch')
                return render_template('add_funds.html')
            
            amount_input = request.form.get('amount', '').strip()
            amount_input = sanitize_input(amount_input)
            
            if amount_input is None:
                flash('Invalid input detected. Possible security threat blocked.', 'error')
                log_activity(username, 'Blocked malicious input in add funds')
                return render_template('add_funds.html')
            
            is_valid, result = validate_numeric_input(amount_input)
            if not is_valid:
                flash(str(result), 'error')
                return render_template('add_funds.html')
            
            amount = float(result)
            
            conn = sqlite3.connect('wallet.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            encrypted_balance = cursor.fetchone()[0]
            current_balance = decrypt_data(encrypted_balance)
            
            if current_balance is None:
                flash('Error retrieving balance', 'error')
                conn.close()
                return render_template('add_funds.html')
            
            new_balance = current_balance + amount
            encrypted_new_balance = encrypt_data(new_balance)
            
            cursor.execute('UPDATE users SET balance = ? WHERE id = ?', (encrypted_new_balance, user_id))
            
            encrypted_amount = encrypt_data(amount)
            cursor.execute('''
                INSERT INTO transactions (user_id, transaction_type, amount)
                VALUES (?, ?, ?)
            ''', (user_id, 'Deposit', encrypted_amount))
            
            conn.commit()
            conn.close()
            
            log_activity(username, f'Added funds: {amount:.2f} crypto')
            flash(f'Successfully added {amount:.2f} crypto to your wallet!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash('An error occurred while adding funds', 'error')
    
    return render_template('add_funds.html')

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    if request.method == 'POST':
        try:
            user_id = session.get('user_id')
            username = session.get('username')
            
            request_user = request.form.get('username', '').strip()
            if request_user and request_user != username:
                flash('Unauthorized modification attempt.', 'error')
                log_activity(username, f'Unauthorized withdraw attempt - User mismatch')
                return render_template('withdraw.html')
            
            amount_input = request.form.get('amount', '').strip()
            amount_input = sanitize_input(amount_input)
            
            if amount_input is None:
                flash('Invalid input detected. Possible security threat blocked.', 'error')
                log_activity(username, 'Blocked malicious input in withdrawal')
                return render_template('withdraw.html')
            
            is_valid, result = validate_numeric_input(amount_input)
            if not is_valid:
                flash(str(result), 'error')
                return render_template('withdraw.html')
            
            amount = float(result)
            
            conn = sqlite3.connect('wallet.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            encrypted_balance = cursor.fetchone()[0]
            current_balance = decrypt_data(encrypted_balance)
            
            if current_balance is None:
                flash('Error retrieving balance', 'error')
                conn.close()
                return render_template('withdraw.html')
            
            if amount > current_balance:
                flash('Insufficient balance', 'error')
                conn.close()
                return render_template('withdraw.html')
            
            new_balance = current_balance - amount
            encrypted_new_balance = encrypt_data(new_balance)
            
            cursor.execute('UPDATE users SET balance = ? WHERE id = ?', (encrypted_new_balance, user_id))
            
            encrypted_amount = encrypt_data(amount)
            cursor.execute('''
                INSERT INTO transactions (user_id, transaction_type, amount)
                VALUES (?, ?, ?)
            ''', (user_id, 'Withdrawal', encrypted_amount))
            
            conn.commit()
            conn.close()
            
            log_activity(username, f'Withdrew funds: {amount:.2f} crypto')
            flash(f'Successfully withdrew {amount:.2f} crypto from your wallet!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash('An error occurred while withdrawing funds', 'error')
    
    return render_template('withdraw.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    username = session.get('username')
    
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            display_name = request.form.get('display_name', '').strip()
            
            email = sanitize_input(email)
            display_name = sanitize_input(display_name)
            
            if email is None or display_name is None:
                flash('Invalid input detected. Please avoid special characters.', 'error')
                log_activity(username, 'Blocked malicious input in profile update')
                return redirect(url_for('profile'))
            
            conn = sqlite3.connect('wallet.db')
            cursor = conn.cursor()
            
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename and file.filename != '':
                    if allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = f"{user_id}_{timestamp}_{filename}"
                        
                        if not os.path.exists(app.config['UPLOAD_FOLDER']):
                            os.makedirs(app.config['UPLOAD_FOLDER'])
                        
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        
                        cursor.execute('UPDATE users SET profile_picture = ? WHERE id = ?', (filename, user_id))
                        log_activity(username, 'Updated profile picture')
                    else:
                        flash('Invalid file type. Only JPG and PNG files are allowed.', 'error')
                        conn.close()
                        return redirect(url_for('profile'))
            
            cursor.execute('UPDATE users SET email = ?, display_name = ? WHERE id = ?', 
                         (email, display_name, user_id))
            
            conn.commit()
            conn.close()
            
            log_activity(username, 'Updated profile information')
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash('An error occurred while updating profile', 'error')
    
    try:
        conn = sqlite3.connect('wallet.db')
        cursor = conn.cursor()
        cursor.execute('SELECT email, display_name, profile_picture FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        
        return render_template('profile.html',
                             username=username,
                             email=user_data[0] or '',
                             display_name=user_data[1] or '',
                             profile_picture=user_data[2])
    except Exception as e:
        flash('An error occurred while loading profile', 'error')
        return redirect(url_for('dashboard'))

@app.route('/transaction', methods=['GET', 'POST'])
@login_required
def transaction():
    if request.method == 'POST':
        try:
            user_id = session.get('user_id')
            username = session.get('username')
            
            request_user = request.form.get('sender_username', '').strip()
            if request_user and request_user != username:
                flash('Unauthorized modification attempt.', 'error')
                log_security(username, 'N/A', 'N/A', 'REJECTED', 'Sender username mismatch')
                log_activity(username, 'Unauthorized transaction attempt - Sender mismatch')
                return render_template('transaction.html')
            
            recipient_username = request.form.get('recipient_username', '').strip()
            amount_input = request.form.get('amount', '').strip()
            
            recipient_username = sanitize_input(recipient_username)
            amount_input = sanitize_input(amount_input)
            
            if not recipient_username or recipient_username is None:
                flash('Invalid recipient username.', 'error')
                log_security(username, 'Invalid', 'N/A', 'REJECTED', 'Invalid recipient username')
                return render_template('transaction.html')
            
            if amount_input is None:
                flash('Invalid input detected. Possible security threat blocked.', 'error')
                log_security(username, recipient_username, 'Invalid', 'REJECTED', 'Malicious input detected')
                log_activity(username, 'Blocked malicious input in transaction')
                return render_template('transaction.html')
            
            is_valid, result = validate_numeric_input(amount_input)
            if not is_valid:
                flash(str(result), 'error')
                log_security(username, recipient_username, amount_input, 'REJECTED', str(result))
                return render_template('transaction.html')
            
            amount = float(result)
            
            if recipient_username == username:
                flash('You cannot send crypto to yourself.', 'error')
                log_security(username, recipient_username, amount, 'REJECTED', 'Self-transfer attempt')
                return render_template('transaction.html')
            
            conn = sqlite3.connect('wallet.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT id, balance FROM users WHERE username = ?', (recipient_username,))
            recipient = cursor.fetchone()
            
            if not recipient:
                flash('Recipient not found.', 'error')
                log_security(username, recipient_username, amount, 'REJECTED', 'Recipient not found')
                conn.close()
                return render_template('transaction.html')
            
            recipient_id = recipient[0]
            
            cursor.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            encrypted_balance = cursor.fetchone()[0]
            sender_balance = decrypt_data(encrypted_balance)
            
            if sender_balance is None:
                flash('Error retrieving balance', 'error')
                log_security(username, recipient_username, amount, 'REJECTED', 'Error retrieving sender balance')
                conn.close()
                return render_template('transaction.html')
            
            if amount > sender_balance:
                flash('Insufficient balance', 'error')
                log_security(username, recipient_username, amount, 'REJECTED', 'Insufficient balance')
                conn.close()
                return render_template('transaction.html')
            
            recipient_encrypted_balance = recipient[1]
            recipient_balance = decrypt_data(recipient_encrypted_balance)
            
            if recipient_balance is None:
                flash('Error retrieving recipient balance', 'error')
                log_security(username, recipient_username, amount, 'REJECTED', 'Error retrieving recipient balance')
                conn.close()
                return render_template('transaction.html')
            
            new_sender_balance = sender_balance - amount
            new_recipient_balance = recipient_balance + amount
            
            encrypted_new_sender_balance = encrypt_data(new_sender_balance)
            encrypted_new_recipient_balance = encrypt_data(new_recipient_balance)
            
            cursor.execute('UPDATE users SET balance = ? WHERE id = ?', (encrypted_new_sender_balance, user_id))
            cursor.execute('UPDATE users SET balance = ? WHERE id = ?', (encrypted_new_recipient_balance, recipient_id))
            
            encrypted_amount = encrypt_data(amount)
            
            cursor.execute('''
                INSERT INTO transactions (user_id, transaction_type, amount, recipient_id, recipient_username)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, 'Transfer Sent', encrypted_amount, recipient_id, recipient_username))
            
            cursor.execute('''
                INSERT INTO transactions (user_id, transaction_type, amount, recipient_id, recipient_username)
                VALUES (?, ?, ?, ?, ?)
            ''', (recipient_id, 'Transfer Received', encrypted_amount, user_id, username))
            
            conn.commit()
            conn.close()
            
            log_activity(username, f'Sent {amount:.2f} crypto to {recipient_username}')
            log_security(username, recipient_username, amount, 'SUCCESS', 'Transaction completed')
            flash(f'Successfully sent {amount:.2f} crypto to {recipient_username}!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash('An error occurred while processing the transaction', 'error')
            log_security(username if username else 'Unknown', recipient_username if recipient_username else 'Unknown', 
                        amount if amount else 'N/A', 'ERROR', str(e))
    
    return render_template('transaction.html')

@app.route('/history')
@login_required
def history():
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        
        conn = sqlite3.connect('wallet.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT transaction_type, amount, recipient_username, timestamp 
            FROM transactions 
            WHERE user_id = ? 
            ORDER BY timestamp DESC
        ''', (user_id,))
        
        transactions = []
        for row in cursor.fetchall():
            trans_type = row[0]
            encrypted_amount = row[1]
            recipient = row[2] or 'N/A'
            timestamp = row[3]
            
            decrypted_amount = decrypt_data(encrypted_amount)
            if decrypted_amount is not None:
                transactions.append({
                    'type': trans_type,
                    'amount': f"{decrypted_amount:.2f}",
                    'recipient': recipient,
                    'timestamp': timestamp
                })
        
        conn.close()
        
        log_activity(username, 'Viewed transaction history')
        
        return render_template('history.html',
                             username=username,
                             transactions=transactions)
        
    except Exception as e:
        flash('An error occurred while loading transaction history', 'error')
        return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error_code=404, error_message='Page not found'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', error_code=500, error_message='An internal error occurred'), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
