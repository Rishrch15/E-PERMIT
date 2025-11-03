from flask import Flask, render_template, request, session, redirect, url_for
import mysql.connector
import sys

app = Flask(__name__)
app.secret_key = 'CCIS.123'

# Database connection details
DB_CONFIG = {
    'host': "localhost",
    'user': "root",
    'password': "",
    'database': "e_permit"
}

def get_db_connection():
    """Establishes and returns a database connection."""
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"Database Connection Error: {err}", file=sys.stderr)
        return None

def create_requests_table(db_conn):
    """Creates the 'requests' table if it doesn't exist."""
    cursor = db_conn.cursor()
    # Define a standard structure for an e-permit request, linking to the 'users' table.
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                request_type VARCHAR(100) NOT NULL,
                date_of_leave DATE NOT NULL,
                reason TEXT NOT NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                date_requested TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- Foreign Key links to the existing 'users' table
                FOREIGN KEY (user_id) REFERENCES users(id) 
            )
        """)
        db_conn.commit()
        print("INFO: 'requests' table checked/created successfully.")
    except mysql.connector.Error as err:
        print(f"Error creating 'requests' table: {err}", file=sys.stderr)
    finally:
        cursor.close()

# Initial database setup and table creation check
db = get_db_connection()
if db:
    # Ensure the required table is created when the app starts
    create_requests_table(db)
    pass 
else:
    print("FATAL: Could not connect to database. Application will likely fail.", file=sys.stderr)


# ---------------- HOME ----------------
@app.route('/')
def home():
    return render_template('index.html')  # Login & Register page

# ---------------- REGISTER ----------------
@app.route('/register', methods=['POST'])
def register():
    cursor = db.cursor()
    
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    existing = cursor.fetchone()

    if existing:
        return render_template('index.html', register_error="Email already exists!")

    cursor.execute(
        "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
        (username, email, password)
    )
    db.commit()
    return render_template('index.html', register_success="Account created! Please login.")

# ---------------- LOGIN ----------------
@app.route('/login', methods=['POST'])
def login():
    cursor = db.cursor()
    email = request.form['email']
    password = request.form['password']

    cursor.execute("SELECT * FROM users WHERE email=%s AND password=%s", (email, password))
    user = cursor.fetchone()

    if user:
        # Assuming the 'id' column is the first column in the 'users' table (index 0)
        session['user_id'] = user[0] 
        session['username'] = user[1] # Assuming username is the second column
        return redirect(url_for('landing'))
    else:
        return render_template('index.html', login_error="Invalid email or password.")
    

# ---------------- LANDING PAGE (DASHBOARD) ----------------
@app.route('/landing', methods=['GET', 'POST'])
def landing():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    cursor = db.cursor()

    if request.method == 'POST':
        # Handles the profile update logic
        department = request.form['department']
        contact_number = request.form['contact_number']
        user_id = session['user_id']

        # Check if profile already exists
        cursor.execute("SELECT * FROM user_profile WHERE user_id=%s", (user_id,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE user_profile 
                SET department=%s, contact_number=%s 
                WHERE user_id=%s
            """, (department, contact_number, user_id))
        else:
            cursor.execute("""
                INSERT INTO user_profile (user_id, department, contact_number)
                VALUES (%s, %s, %s)
            """, (user_id, department, contact_number))

        db.commit()
        
    # Fetch joined user data (Profile info)
    cursor.execute("""
        SELECT u.username, u.email, p.department, p.contact_number
        FROM users u
        LEFT JOIN user_profile p ON u.id = p.user_id
        WHERE u.id=%s
    """, (session['user_id'],))
    user = cursor.fetchone()

    # Fetch user's requests (This is the query that was causing the error before)
    try:
        cursor.execute("""
            SELECT id, request_type, date_of_leave, reason, status, date_requested
            FROM requests
            WHERE user_id=%s
            ORDER BY date_requested DESC
        """, (session['user_id'],))
        requests_list = cursor.fetchall()
    except mysql.connector.Error as err:
        print(f"Error fetching requests: {err}", file=sys.stderr)
        requests_list = []


    return render_template('LandingPage.html', user=user, requests=requests_list)

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
