from flask import Flask, render_template, request, session, redirect, url_for, flash
import mysql.connector
import sys
from datetime import datetime 

app = Flask(__name__)
app.secret_key = 'CCIS.123' 

DB_CONFIG = {
    'host': "localhost",
    'user': "root",
    'password': "",
    'database': "e_permit"
}

def get_db_connection():
    """Establishes a connection to the MySQL database."""
    try:
        return mysql.connector.connect(**DB_CONFIG, buffered=True)
    except mysql.connector.Error as err:
        print(f"Database Connection Error: {err}", file=sys.stderr)
        return None

def initialize_db():
    """Creates the necessary tables if they don't exist."""
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
    
    db.commit()
    cursor.close()
    db.close()
    print("INFO: Tables checked/created successfully.")

initialize_db()


# ---------------- HOME ----------------
@app.route('/')
def home():
    """Renders the main index page."""
    return render_template('index.html')

# ---------------- REGISTER ----------------
@app.route('/register', methods=['POST'])
def register():
    """Handles new user registration."""
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

    if existing:
        cursor.close()
        db.close()
        flash("Email already exists! Please login.", "danger") 
        return redirect(url_for('login'))

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s,%s,%s)",
            (username, email, password)
        )
        db.commit()
        flash("Account created! Please login.", "success")
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"Error during registration: {e}", file=sys.stderr)
        flash("An error occurred during registration. Please try again.", "danger")
        return redirect(url_for('home'))
        
    finally:
        cursor.close()
        db.close()

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and session creation."""
    if request.method == 'GET':
        return render_template('login.html')

    db = get_db_connection()
    if not db:
        flash("Login failed due to a database error.", "danger")
        return render_template('login.html')
        
    cursor = db.cursor()
    email = request.form['email']
    password = request.form['password']

    cursor.execute("SELECT id, username FROM users WHERE email=%s AND password=%s", (email, password))
    user = cursor.fetchone()
    
    cursor.close()
    db.close()

    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        flash(f"Welcome back, {user[1]}!", "success")
        return redirect(url_for('landing'))
    else:
        flash("Invalid email or password.", "danger")
        return render_template('login.html')

# ---------------- LANDING (UPDATED) ----------------
@app.route('/landing', methods=['GET', 'POST'])
def landing():
    """Renders the user dashboard, handles profile updates, and fetches requests."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

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
        SELECT id, request_type, item, quantity, date_needed, purpose, location_from, location_to, status, date_requested
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

    item = None
    quantity = None
    date_needed = None
    purpose = None
    location_from = None
    location_to = None

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
        if quantity_str and quantity_str.isdigit():
            quantity = int(quantity_str)
        else:
            quantity = 1 
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

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    """Clears the user session and redirects to login."""
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)