from flask import Flask, render_template, request, session, redirect, url_for, flash
import mysql.connector
import sys
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt 
import random
import smtplib
from email.mime.text import MIMEText
import uuid 

app = Flask(__name__)
app.secret_key = 'CCIS.123'

bcrypt = Bcrypt(app)

DB_CONFIG = {
    'host': "localhost",
    'user': "root",
    'password': "",
    'database': "e_permit"
}

ADMIN_USER_ID = 3

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_ADDRESS = 'irocha.k12152432@umak.edu.ph' 
EMAIL_PASSWORD = 'bygo dfwz vgfg fwav'


def get_db_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG, buffered=True)
    except mysql.connector.Error as err:
        print(f"Database Connection Error: {err}", file=sys.stderr)
        return None


def initialize_db():
    """Ensures all tables exist in the database."""
    db = get_db_connection()
    if not db:
        print("FATAL: Could not connect to database.", file=sys.stderr)
        return

    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_profile (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            department VARCHAR(50),
            contact_number VARCHAR(20),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            request_type VARCHAR(50) NOT NULL,
            item VARCHAR(255),
            quantity INT DEFAULT 1,
            date_needed DATE NOT NULL,
            purpose TEXT,
            location_from VARCHAR(255),
            location_to VARCHAR(255),
            status VARCHAR(50) DEFAULT 'Pending',
            date_requested TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token VARCHAR(100) PRIMARY KEY,
            user_id INT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    db.commit()
    cursor.close()
    db.close()
    print("INFO: Tables checked/created successfully.")


initialize_db()

# ---------------- EMAIL UTILITIES ----------------

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(recipient_email, otp_code):
    try:
        msg = MIMEText(f"Your E-Permit Registration Code is: {otp_code}\n\nThis code expires shortly. Do not share it.")
        msg['Subject'] = 'E-Permit Email Verification Code'
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = recipient_email

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls() 
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, recipient_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}", file=sys.stderr)
        return False

def send_reset_email(recipient_email, reset_token):
    try:
        reset_url = url_for('reset_password', token=reset_token, _external=True)

        msg = MIMEText(f"You requested a password reset for your E-Permit account. "
                       f"Click the link below to reset your password:\n\n{reset_url}\n\n"
                       f"This link will expire shortly (1 hour).")
        msg['Subject'] = 'E-Permit Password Reset Request'
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = recipient_email

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, recipient_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending password reset email: {e}", file=sys.stderr)
        return False


# ---------------- HOME ----------------
@app.route('/')
def home():
    """Renders the main index page."""
    return render_template('index.html')


# ---------------- REGISTER ----------------
@app.route('/register', methods=['POST'])
def register():
    """Handles new user registration by sending an OTP instead of final database commit."""
    db = get_db_connection()
    if not db:
        flash("Registration failed due to a database error.", "danger")
        return redirect(url_for('home'))

    cursor = db.cursor()
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    existing = cursor.fetchone()
    cursor.close()
    db.close()

    if existing:
        flash("Email already exists! Please login.", "danger")
        return redirect(url_for('login'))

    otp_code = generate_otp()
    
    session['otp_user_data'] = {
        'username': username,
        'email': email,
        'password_hash': bcrypt.generate_password_hash(password).decode('utf-8'),
        'otp_code': otp_code
    }

    if send_otp_email(email, otp_code):
        flash("A verification code has been sent to your email. Please check your inbox.", "info")
        return redirect(url_for('verify_otp'))
    else:
        session.pop('otp_user_data', None)
        flash("Failed to send verification email. Please check server configuration.", "danger")
        return redirect(url_for('home'))

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    """Handles OTP verification and final user insertion into the database."""
    user_data = session.get('otp_user_data')
    if not user_data:
        flash("Verification process expired or started incorrectly. Please register again.", "danger")
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('login.html') 

    entered_otp = request.form.get('otp_code')
    stored_otp = user_data.get('otp_code')
    
    if entered_otp == stored_otp:
        db = get_db_connection()
        if not db:
            flash("Database error during final registration.", "danger")
            return redirect(url_for('home'))

        cursor = db.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s,%s,%s)",
                (user_data['username'], user_data['email'], user_data['password_hash'])
            )
            db.commit()

            session.pop('otp_user_data', None)

            flash("Email verified and account created! You can now log in.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            print(f"Error during final registration: {e}", file=sys.stderr)
            flash("An error occurred during final step. Please try again.", "danger")
            return redirect(url_for('home'))

        finally:
            cursor.close()
            db.close()

    else:
        flash("Invalid verification code. Please try again.", "danger")
        return render_template('login.html') 


# ---------------- LOGIN with hashing ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and session creation."""
    if request.method == 'GET' and 'otp_user_data' in session:
        return redirect(url_for('verify_otp'))

    if request.method == 'GET':
        return render_template('login.html')

    db = get_db_connection()
    if not db:
        flash("Login failed due to a database error.", "danger")
        return render_template('login.html')

    cursor = db.cursor()
    email = request.form['email']
    password = request.form['password']  

    cursor.execute("SELECT id, username, password FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()    
    cursor.close()
    db.close()

    if user and bcrypt.check_password_hash(user[2], password):
        session['user_id'] = user[0]
        session['username'] = user[1]
        flash(f"Welcome back, {user[1]}!", "success")

        if user[0] == ADMIN_USER_ID:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('landing'))
    else:
        flash("Invalid email or password.", "danger")
        return render_template('login.html')

# ---------------- FORGOT PASSWORD ----------------

@app.route('/forgot-password-request', methods=['POST']) 
def forgot_password_request():
    """
    Handles the request to start the password reset process (sending the email).
    Generates a token and stores it in the database.
    """
    email = request.form.get('email')
    
    db = get_db_connection()
    if not db:
        flash("Password reset failed due to a database error.", "danger")
        return redirect(url_for('login'))
    
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    
    flash("A password reset link has been sent to your email.", 'success')
    
    if user:
        user_id = user[0]
        reset_token = str(uuid.uuid4()) 
        expires_at = datetime.now() + timedelta(hours=1) 

        try:
            cursor.execute("DELETE FROM password_reset_tokens WHERE user_id = %s", (user_id,))
            
            cursor.execute(
                "INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (%s, %s, %s)",
                (reset_token, user_id, expires_at)
            )
            db.commit()
            
            if not send_reset_email(email, reset_token):
                 print(f"WARNING: Failed to send reset email for user {user_id}", file=sys.stderr)

        except Exception as e:
            print(f"Error generating/saving reset token: {e}", file=sys.stderr)
        finally:
            cursor.close()
            db.close()
    else:
        cursor.close()
        db.close()

    return redirect(url_for('login'))


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
   
    db = get_db_connection()
    if not db:
        flash("Database error during password reset.", "danger")
        return redirect(url_for('login'))
        
    cursor = db.cursor()
    
    cursor.execute(
        "SELECT user_id FROM password_reset_tokens WHERE token=%s AND expires_at > %s",
        (token, datetime.now())
    )
    token_data = cursor.fetchone()
    
    if not token_data:
        cursor.close()
        db.close()
        flash("The password reset link is invalid or has expired. Please request a new one.", 'danger')
        return redirect(url_for('login'))

    user_id = token_data[0]

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not new_password or new_password != confirm_password:
            flash("Passwords do not match or are empty.", 'danger')
            return render_template('reset_password.html', token=token)

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        try:
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
            
            cursor.execute("DELETE FROM password_reset_tokens WHERE token = %s", (token,))
            db.commit()

            flash("Your password has been successfully reset! You can now log in.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error updating password: {e}", file=sys.stderr)
            flash("An error occurred while resetting the password. Please try again.", 'danger')
            return render_template('reset_password.html', token=token)
        finally:
            cursor.close()
            db.close()

    cursor.close()
    db.close()
    return render_template('reset_password.html', token=token)


# ---------------- LANDING Page----------------
@app.route('/landing', methods=['GET', 'POST'])
def landing():
    """Displays the user landing page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['user_id'] == ADMIN_USER_ID:
        return redirect(url_for('admin_dashboard'))

    db = get_db_connection()
    if not db:
        flash("Could not load dashboard data due to a database error.", "danger")
        return redirect(url_for('logout'))

    cursor = db.cursor()
    user_id = session['user_id']

    if request.method == 'POST':
        department = request.form.get('department')
        contact_number = request.form.get('contact_number')

        cursor.execute("SELECT * FROM user_profile WHERE user_id=%s", (user_id,))
        existing = cursor.fetchone()

        try:
            if existing:
                cursor.execute("""
                    UPDATE user_profile
                    SET department=%s, contact_number=%s
                    WHERE user_id=%s
                """, (department, contact_number, user_id))
            else:
                cursor.execute("""
                    INSERT INTO user_profile (user_id, department, contact_number)
                    VALUES (%s,%s,%s)
                """, (user_id, department, contact_number))
            db.commit()
            flash("Profile updated successfully!", "info")
        except Exception as e:
            print(f"Error updating profile: {e}", file=sys.stderr)
            flash("Failed to update profile.", "danger")

    cursor.execute("""
        SELECT u.username, u.email, p.department, p.contact_number
        FROM users u
        LEFT JOIN user_profile p ON u.id = p.user_id
        WHERE u.id=%s
    """, (user_id,))
    user = cursor.fetchone()

    cursor.execute("""
        SELECT id, request_type, item, quantity, date_needed, purpose, 
                location_from, location_to, status, date_requested
        FROM requests
        WHERE user_id=%s
        ORDER BY date_requested DESC
    """, (user_id,))
    requests_list = cursor.fetchall()

    cursor.close()
    db.close()

    pending_requests = [req for req in requests_list if req[8] == 'Pending']
    history_requests = [req for req in requests_list if req[8] != 'Pending']

    return render_template(
        'LandingPage.html',
        user=user,
        pending_requests=pending_requests,
        history_requests=history_requests
    )


# ---------------- ADD REQUEST ----------------
@app.route('/add_request', methods=['POST'])
def add_request():
    """Handles the submission of a new borrow or transfer request."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db_connection()
    if not db:
        flash("Failed to submit request: Database connection error.", "danger")
        return redirect(url_for('landing'))

    cursor = db.cursor()
    user_id = session['user_id']
    request_type = request.form.get('requestType')

    item = quantity = date_needed = purpose = location_from = location_to = None

    if request_type == 'Borrow':
        item = request.form.get('borrowItem')
        quantity_str = request.form.get('borrowQuantity')
        date_needed = request.form.get('borrowDate')
        purpose = request.form.get('borrowEvent')

    elif request_type == 'Transfer':
        item = request.form.get('transferEquipment')
        quantity_str = request.form.get('transferQuantity')
        date_needed = request.form.get('transferDate')
        location_from = request.form.get('transferFrom')
        location_to = request.form.get('transferTo')

    else:
        cursor.close()
        db.close()
        flash("Invalid request type submitted.", "danger")
        return redirect(url_for('landing'))

    if not item or not date_needed:
        cursor.close()
        db.close()
        flash("Please fill in the Item/Equipment and Date Needed fields.", "danger")
        return redirect(url_for('landing'))

    try:
        quantity = int(quantity_str) if quantity_str and quantity_str.isdigit() else 1
    except ValueError:
        quantity = 1

    try:
        datetime.strptime(date_needed, '%Y-%m-%d')
    except ValueError:
        cursor.close()
        db.close()
        flash("Invalid date format submitted for 'Date Needed'.", "danger")
        return redirect(url_for('landing'))

    try:
        cursor.execute("""
            INSERT INTO requests
            (user_id, request_type, item, quantity, date_needed, purpose, location_from, location_to)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, request_type, item, quantity, date_needed, purpose, location_from, location_to))
        db.commit()
        flash("Request submitted successfully!", "success")
    except Exception as e:
        print(f"Error inserting request: {e}", file=sys.stderr)
        flash("Failed to submit request. Please check server logs.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect(url_for('landing'))

@app.route('/cancel_request/<int:req_id>', methods=['POST'])
def cancel_request(req_id):
    db = get_db_connection()
    if not db:
        flash("Database connection failed.", "danger")
        return redirect(url_for('landing'))

    cursor = db.cursor()
    try:
        cursor.execute("UPDATE requests SET status = %s WHERE id = %s", ("Cancelled", req_id))
        db.commit()
        flash("Request has been cancelled.", "warning")
    except Exception as e:
        print(f"Error cancelling request: {e}", file=sys.stderr)
        flash("Failed to cancel the request.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect(url_for('landing'))



@app.route('/delete_request/<int:req_id>', methods=['POST'])
def delete_request(req_id):
    db = get_db_connection()
    if not db:
        flash("Database connection failed.", "danger")
        return redirect(url_for('landing'))
        
    cursor = db.cursor()

    try:
        cursor.execute("DELETE FROM requests WHERE id = %s LIMIT 1", (req_id,))
        db.commit()
        flash("Request has been deleted.", "danger")
    except Exception as e:
        print(f"Error deleting request: {e}", file=sys.stderr)
        flash("Failed to delete the request.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect(url_for('landing')) 


# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    """Clears the user session and redirects to login."""
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))


# ---------------- ADMIN DASHBOARD ----------------
@app.route('/admin_dashboard')
def admin_dashboard():
    """Fetches all PENDING and HISTORY requests for the admin to review."""
    if 'user_id' not in session or session['user_id'] != ADMIN_USER_ID:
        flash("Access denied. You must be an administrator.", "danger")
        return redirect(url_for('login'))

    db = get_db_connection()
    if not db:
        flash("Could not load data due to a database error.", "danger")
        return render_template('AdminDashboard.html', pending_requests=[], history_requests=[], active_tab='pending')

    cursor = db.cursor()

    cursor.execute("""
        SELECT r.id, u.username, r.request_type, r.item, r.quantity, r.date_needed,
                r.purpose, r.location_from, r.location_to, r.date_requested
        FROM requests r
        JOIN users u ON r.user_id = u.id
        WHERE r.status = 'Pending'
        ORDER BY r.date_requested ASC
    """)
    pending_requests = cursor.fetchall()

    cursor.execute("""
        SELECT r.id, u.username, r.request_type, r.item, r.quantity, r.date_needed,
                r.purpose, r.location_from, r.location_to, r.date_requested, r.status
        FROM requests r
        JOIN users u ON r.user_id = u.id
        WHERE r.status IN ('Approved', 'Rejected', 'Cancelled')
        ORDER BY r.date_requested DESC
    """)
    history_requests = cursor.fetchall()

    cursor.close()
    db.close()

    active_tab = request.args.get('tab', 'pending')

    return render_template(
        'AdminDashboard.html',
        pending_requests=pending_requests,
        history_requests=history_requests,
        active_tab=active_tab
    )


# ---------------- UPDATE REQUEST STATUS ----------------
@app.route('/update_request_status', methods=['POST'])
def update_request_status():
    """Handles admin action to approve or reject a request."""
    if 'user_id' not in session or session['user_id'] != ADMIN_USER_ID:
        flash("Authorization failed.", "danger")
        return redirect(url_for('login'))

    db = get_db_connection()
    if not db:
        flash("Failed to process action due to a database error.", "danger")
        return redirect(url_for('admin_dashboard'))

    cursor = db.cursor()
    request_id = request.form.get('request_id')
    new_status = request.form.get('action')

    if not request_id or new_status not in ['Approved', 'Rejected']:
        flash("Invalid request data provided.", "danger")
        cursor.close()
        db.close()
        return redirect(url_for('admin_dashboard'))

    try:
        cursor.execute("SELECT status FROM requests WHERE id = %s", (request_id,))
        current_status = cursor.fetchone()

        if current_status and current_status[0] == 'Pending':
            cursor.execute(
                "UPDATE requests SET status = %s WHERE id = %s",
                (new_status, request_id)
            )
            db.commit()
            flash(f"Request #{request_id} has been successfully {new_status.lower()}.", "success")
        else:
            flash(f"Request #{request_id} status is already {current_status[0].lower()} and cannot be changed.", "warning")

    except Exception as e:
        print(f"Error updating request status: {e}", file=sys.stderr)
        flash("An unexpected database error occurred.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect(url_for('admin_dashboard', tab='history'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)