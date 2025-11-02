from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "CCIS.123" 

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",      
            password="",      
            database="e_permit"
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None


@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('SignUp/LogIn'))
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not (username and email and password):
        flash("All fields are required for registration.", "danger")
        return redirect(url_for('home'))
        
    hashed_pw = generate_password_hash(password)

    conn = get_db_connection()
    if conn is None:
        flash("Server error: Could not connect to the database.", "danger")
        return redirect(url_for('home'))

    cursor = conn.cursor()

    try:
        cursor.execute("SELECT username, email FROM users WHERE username = %s OR email = %s", (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            if existing_user[0] == username:
                flash("Username already exists. Please try another.", "danger")
            elif existing_user[1] == email:
                flash("Email is already registered.", "danger")
            return redirect(url_for('home'))

        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                       (username, email, hashed_pw))
        conn.commit()
        flash("Registration successful! You can now log in.", "success")
        
    except mysql.connector.Error as err:
        flash(f"A database error occurred during registration. Details: {err}", "danger")
        conn.rollback()
        
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('home'))

# ---------- Login Route ---------- #
@app.route('/login', methods=['POST'])
def login():
    """Handles user login, verifying credentials and setting the session."""
    username = request.form.get('username')
    password = request.form.get('password')

    conn = get_db_connection()
    if conn is None:
        flash("Server error: Could not connect to the database.", "danger")
        return redirect(url_for('home'))

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user['password'], password):
        session['user'] = user['username']
        flash("Login successful!", "success")
        return redirect(url_for('landing'))
    else:
        flash("Invalid username or password", "danger")
        return redirect(url_for('home'))

# ---------- Landing Page (After Login) ---------- #
@app.route('/landing')
def landing():
    """Renders the protected dashboard page for logged-in users."""
    if 'user' in session:
        return render_template('LandingPage.html', username=session['user'])
    else:
        flash("You need to log in to view this page.", "warning")
        return redirect(url_for('home'))

# ---------- Logout ---------- #
@app.route('/logout')
def logout():
    """Clears the user session and redirects to home."""
    session.pop('user', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

# ---------------- Run Server ---------------- #
if __name__ == '__main__':
    app.run(debug=True)
