from flask import Flask, request, render_template, session, redirect, url_for, flash, make_response, Response, jsonify, send_from_directory, abort
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import sqlite3
import time
import random
import urllib.parse
import base58
import hashlib
import os
import subprocess
import re
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Constants for rate limiting
RATE_LIMIT_ATTEMPTS = 3  # Changed to 3 failed attempts
RATE_LIMIT_BLOCK_DURATION = timedelta(hours=1)  # Block for 1 hour
RATE_LIMIT_WINDOW = timedelta(minutes=15)  # 15-minute window for tracking attempts

# Store login attempts per IP
ip_attempts = {}

def get_client_ip():
    """Extract the client IP address, considering proxies."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr

def get_db_connection():
    conn = sqlite3.connect("vulnerable.db")  # Replace with the path to your database
    conn.row_factory = sqlite3.Row  # This makes rows behave like dictionaries
    return conn

# Customer Portal (formerly employee login)
@app.route("/customer-login", methods=["GET", "POST"])
def customer_login():
    # Initialize variables
    error = ""
    show_2fa = False
    emp_username = ""
    emp_password = ""

    client_ip = get_client_ip()
    current_time = datetime.now()

    # Initialize IP tracking if not exist
    if client_ip not in ip_attempts:
        ip_attempts[client_ip] = {
            "attempts": 0,
            "reset_time": current_time + RATE_LIMIT_WINDOW,
            "block_until": None
        }

    # Check if IP is currently blocked
    if ip_attempts[client_ip]["block_until"] and current_time < ip_attempts[client_ip]["block_until"]:
        remaining_block_time = int((ip_attempts[client_ip]["block_until"] - current_time).total_seconds() / 60)
        error = f"This IP has been blocked for too many failed attempts. Try again in {remaining_block_time} minutes."
        return render_template("customer_login.html", error=error, show_2fa=show_2fa,
                             emp_username=emp_username, emp_password=emp_password)

    # Reset attempts if the reset time has passed
    if current_time >= ip_attempts[client_ip]["reset_time"]:
        ip_attempts[client_ip] = {
            "attempts": 0,
            "reset_time": current_time + RATE_LIMIT_WINDOW,
            "block_until": None
        }

    # Handle GET request
    if request.method == "GET":
        return render_template("customer_login.html", error=error, show_2fa=show_2fa,
                             emp_username=emp_username, emp_password=emp_password)

    # Handle POST request
    emp_username = request.form.get("emp_username", "")
    emp_password = request.form.get("emp_password", "")
    two_fa_code = request.form.get("two_fa_code", "")
    stay_logged_in = request.form.get("stay_logged_in", "")

    # Check if IP has reached max attempts
    if ip_attempts[client_ip]["attempts"] >= RATE_LIMIT_ATTEMPTS:
        ip_attempts[client_ip]["block_until"] = current_time + RATE_LIMIT_BLOCK_DURATION
        error = f"This IP has been blocked for too many failed attempts. Try again in 60 minutes."
        return render_template("customer_login.html", error=error, show_2fa=show_2fa,
                            emp_username=emp_username, emp_password=emp_password)

    # Query database for user
    conn = sqlite3.connect("uenumrestim.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM companyp WHERE username = ? AND password = ?", (emp_username, emp_password))
    employee = cursor.fetchone()
    conn.close()

    if not employee:
        # Increment attempts for ANY failed login
        ip_attempts[client_ip]["attempts"] += 1
        
        # Check username existence for timing attack simulation
        conn = sqlite3.connect("uenumrestim.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM companyp WHERE username = ?", (emp_username,))
        emp_exists = cursor.fetchone()
        conn.close()

        if emp_username == "as400":
            time.sleep(0)
            error = "Invalid credentials."
        elif not emp_exists or emp_username == "albuquerque":
            time.sleep(0.01)
            error = "Invalid credentials."
        else:
            error = "Invalid credentials."
            
        return render_template("customer_login.html", error=error, show_2fa=show_2fa,
                             emp_username=emp_username, emp_password=emp_password)

    # At this point, employee exists and credentials are valid
    # Store username in session for 2FA verification
    session["pending_username"] = emp_username
    session["stay_logged_in"] = bool(stay_logged_in)
            
    # Successful login - reset attempts
    ip_attempts[client_ip]["attempts"] = 0
    ip_attempts[client_ip]["reset_time"] = current_time + RATE_LIMIT_WINDOW
    ip_attempts[client_ip]["block_until"] = None

# If 2FA code was submitted, verify it
    if "emp_code" in request.form or two_fa_code:
        # Use whichever code was submitted
        submitted_code = request.form.get("emp_code") or two_fa_code
        stored_2fa_code = session.get("2fa_code")
        stored_2fa_timestamp = session.get("2fa_timestamp")
                
        if stored_2fa_code and stored_2fa_timestamp:
            elapsed_time = datetime.now() - datetime.fromisoformat(stored_2fa_timestamp)
            if elapsed_time.total_seconds() <= 600:  # 10 minutes
                if str(submitted_code).zfill(2) == str(stored_2fa_code).zfill(2):
                    # Successful 2FA verification
                    session["authenticated"] = True
                    session["username"] = session.pop("pending_username", None)
                    session["logged_in"] = True
                            
                    # Create response with redirect
                    response = make_response(redirect(url_for("customer_dashboard")))
                    
                    # Set stay_logged_in cookie if checkbox was checked
                    if request.form.get("stay_logged_in") == "1":
                        sha1_username = hashlib.sha1(emp_username.encode("utf-8")).hexdigest()
                        response.set_cookie(
                            'stay_logged_in',
                            value=sha1_username,
                            max_age=86400,  # 24 hours
                            path='/',
                            secure=False,
                            httponly=False,
                            samesite='Lax'
                        )
                    
                    return response
                else:
                    error = "Invalid 2FA code."
                    show_2fa = True
                    ip_attempts[client_ip]["attempts"] += 1
            else:
                # Instance 1 (expired code):
                generated_2fa_code = f"{random.randint(0, 99):02d}"
                session["2fa_code"] = generated_2fa_code
                session["2fa_timestamp"] = datetime.now().isoformat()
                error = "2FA code has expired. New code generated."
                show_2fa = True
        else:
            # Instance 2 (no valid 2FA session):
            generated_2fa_code = f"{random.randint(0, 99):02d}"
            session["2fa_code"] = generated_2fa_code
            session["2fa_timestamp"] = datetime.now().isoformat()
            show_2fa = True
    else:
        # No 2FA code submitted, show 2FA input
        if not session.get("2fa_code"):
            # Instance 3 (first time or no code):
            generated_2fa_code = f"{random.randint(0, 99):02d}"
            session["2fa_code"] = generated_2fa_code
            session["2fa_timestamp"] = datetime.now().isoformat()
        show_2fa = True

    return render_template("customer_login.html", error=error, show_2fa=show_2fa,
                        emp_username=emp_username, emp_password=emp_password,
                        stay_logged_in=request.form.get("stay_logged_in") == "1")

# User Portal
@app.route("/user-login", methods=["GET", "POST"])
def user_login():
    error = ""
    username = ""
    password = ""
    if request.method == "POST":
        print("User Login - Session before:", dict(session))
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Whitelist of allowed characters
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_@.")

        if username and not all(c in allowed_chars for c in username.replace("'", "").replace(" ", "").replace("=", "").replace("or", "").replace("1", "")):
            error = "Invalid credentials. Please try again."
            return render_template("user_login.html", error=error, username=username, password=password)

        # SQL injection vulnerability
        if username and "' or 1=1--" in username.lower():
            return render_template("user_portal.html", username="hacker", email="hacker@example.com")

        # Rate limiting
        current_time = time.time()
        if hasattr(user_login, 'last_query_time') and current_time - user_login.last_query_time < 0.1:
            error = "Please try again later."
            return render_template("user_login.html", error=error, username=username, password=password)
        user_login.last_query_time = current_time

        # Database operations
        try:
            conn = sqlite3.connect("vulnerable.db")
            cursor = conn.cursor()
            query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
            cursor.execute(query)
            user = cursor.fetchone()

            if user:        
                session.clear()
                session["username"] = user[1]
                session["encoded_username"] = base58.b58encode(user[1].encode("utf-8")).decode("utf-8")
                print("User Login - Session after:", dict(session))  # Add debug print
                return redirect(url_for("profile"))

            # User enumeration
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user_exists = cursor.fetchone()
            cursor.close()
            conn.close()

            if user_exists:
                error = "Invalid credentials.  Please try again."  # Two spaces
            else:
                error = "Invalid credentials. Please try again. "  # One space

        except sqlite3.Error as e:
            error = "Invalid credentials. Please try again."
            if 'cursor' in locals() and cursor:
                cursor.close()
            if 'conn' in locals() and conn:
                conn.close()

    return render_template("user_login.html", error=error, username=username, password=password)

@app.route("/profile", methods=["GET", "POST"])
def profile():
    print("Profile - Session state:", dict(session))
    if "username" not in session:
        return redirect(url_for('user_login'))

    is_admin = bool(session.get('is_admin', False))

    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    error = None
    success = None

    current_username = session["username"]
    if "encoded_username" not in session:
        session["encoded_username"] = base58.b58encode(current_username.encode("utf-8")).decode("utf-8")
    encoded_username = session["encoded_username"]
    session['logged_in'] = True

    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()

        cursor.execute("SELECT email, balance FROM users WHERE username = ?", (current_username,))
        result = cursor.fetchone()
        if result:
            email = result[0]
            balance = result[1]

        cursor.execute("""
            SELECT COUNT(*)
            FROM purchases
            WHERE user_id = ?
        """, (session['username'],))
        total_items = cursor.fetchone()[0]
        total_pages = (total_items + per_page - 1) // per_page

        cursor.execute("""
            SELECT p.date, p.title, p.amount, p.code, COALESCE(gc.used, 0) as used
            FROM purchases p
            LEFT JOIN gift_card_codes gc ON p.code = gc.code
            WHERE p.user_id = ?
            ORDER BY p.date DESC
            LIMIT ? OFFSET ?
        """, (session['username'], per_page, offset))
        purchases = cursor.fetchall()

        if request.method == "POST":
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_new_password")
            submitted_encoded_username = request.form.get("encoded_username", encoded_username)

            if new_password != confirm_password:
                error = "Passwords do not match. Please try again."
            else:
                decoded_username = base58.b58decode(submitted_encoded_username).decode("utf-8")
                cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, decoded_username))

                if cursor.rowcount == 0:
                    error = "No matching user found to update the password."
                else:
                    success = f"Password for user '{decoded_username}' has been reset."
                conn.commit()

    except Exception as e:
        error = f"Failed to fetch data: {str(e)}"
        purchases = []
        total_pages = 1
    finally:
        conn.close()

    return render_template("profile.html",
                           error=error,
                           success=success,
                           username=current_username,
                           encoded_username=encoded_username,
                           email=email,
                           balance=balance,
                           purchases=purchases,
                           current_page=page,
                           total_pages=total_pages,
                           admin_panel=is_admin,
                           flag="flag[fl4w3d_st4t3_m4ch1n3_byp4ss]" if is_admin else None)

@app.route("/it-login", methods=["GET", "POST"])
def it_login():
    if request.method == "POST":
        print("IT Login - Session before:", dict(session))  # Add debug print
        
        # If user is logged in, grant admin regardless of credentials
        if 'username' in session:
            session['is_admin'] = True
            print("IT Login - Session after:", dict(session))  # Add debug print
            return render_template("it_login.html", error="Invalid credentials")
        
        # Normal flow if not logged in    
        password = request.form.get("password", "")
        if password == "admin123":
            session['is_admin'] = True
            return redirect(url_for("profile"))
            
        return render_template("it_login.html", error="Invalid credentials")
            
    return render_template("it_login.html")

@app.route("/customer-dashboard")
def customer_dashboard():
    # First check for stay_logged_in cookie
    stay_logged_in_cookie = request.cookies.get('stay_logged_in')
    if stay_logged_in_cookie:
        # Try to find user by their hashed username
        try:
            conn = sqlite3.connect("uenumrestim.db")
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM companyp")
            users = cursor.fetchall()
            conn.close()
            
            # Check if the cookie matches any user's hashed username
            for user in users:
                username = user[0]
                hashed = hashlib.sha1(username.encode("utf-8")).hexdigest()
                if hashed == stay_logged_in_cookie:
                    # Found matching user, set session and render dashboard
                    session["authenticated"] = True
                    session["username"] = username
                    session["logged_in"] = True
                    
                    if username == "user2":
                        flag = "FLAG{BruteForce_Cookie_Success}"
                        return render_template("customer_dashboard.html", emp_username=username, flag=flag)
                    return render_template("customer_dashboard.html", emp_username=username)
        except Exception as e:
            print(f"Error checking stay_logged_in cookie: {e}")

    # If no valid cookie, check session authentication
    if not session.get("authenticated"):
        error = "You must be logged in to see your profile."
        return render_template("customer_login.html", error=error)

    username = session.get("username")
    if username:
        if username == "user2":
            flag = "FLAG{BruteForce_Cookie_Success}"
            return render_template("customer_dashboard.html", emp_username=username, flag=flag)
        return render_template("customer_dashboard.html", emp_username=username)
    
    return redirect(url_for("login"))

@app.route('/logout', methods=['GET', 'POST'])  # Explicitly specify methods
def logout():
    try:
        # Verify request method
        if request.method not in ['GET', 'POST']:
            abort(405)  # Method Not Allowed
            
        # Check if user is actually logged in
        if not session.get('authenticated') and not session.get('logged_in'):
            flash('No active session to logout from.', 'warning')
            return redirect(url_for('login'))
            
        # Store flag-related session data
        found_flags = session.get('found_flags', [])
        display_mode = session.get('display_mode', 'black')
        
        # Clear session
        session.clear()
        
        # Restore flag-related data
        session['found_flags'] = found_flags
        session['display_mode'] = display_mode
        
        # Create response and delete authentication cookies
        response = make_response(redirect('/user-login'))
        
        # Delete all authentication-related cookies
        cookies_to_delete = ['stay_logged_in', 'session']
        for cookie in cookies_to_delete:
            response.delete_cookie(cookie, path='/')
            response.delete_cookie(cookie, path='/static/')
            response.delete_cookie(cookie, domain='localhost')
        
        flash('Successfully logged out.', 'success')
        return response
        
    except Exception as e:
        flash(f'Error during logout: {str(e)}', 'danger')
        return redirect(url_for('/'))

@app.route('/')
def index():
    return redirect(url_for("news_article")) # Redirects to /news-article

# Background image route
@app.route('/static/background/<path:filename>')
def serve_background(filename):
    return send_from_directory('static/background', filename)

# Combined security and caching headers
@app.after_request
def add_headers(response):
    # Cache control (only add if not already present)
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'public, max-age=31536000'
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block' # Could block future XSS vuln
    
    return response

# Static file versioning for cache busting
@app.context_processor
def utility_processor():
    def versioned_static(filename):
        fullpath = os.path.join(app.root_path, 'static', filename)
        try:
            timestamp = str(os.path.getmtime(fullpath))
            return url_for('static', filename=filename, v=timestamp)
        except OSError:
            return url_for('static', filename=filename)
    return dict(versioned_static=versioned_static)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Input validation for username to prevent SSTI and XSS
        if not username or not email or not password or not confirm_password:
            error = "All fields are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif not is_valid_username(username):
            error = "Username can only contain letters, numbers, and underscores."
        elif not is_valid_email(email):
            error = "Please enter a valid email address."
        else:
            try:
                # Directly connect to vulnerable.db
                conn = sqlite3.connect('vulnerable.db')
                cursor = conn.cursor()
                
                # Check if the username already exists
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                existing_username = cursor.fetchone()
                
                # Check if the email already exists
                cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
                existing_email = cursor.fetchone()
                
                if existing_username:
                    error = "Username is already taken."
                elif existing_email:
                    error = "Email is already registered."
                else:
                    # Insert the new user into the database
                    cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                                   (username, email, password))
                    conn.commit()
                    conn.close()
                    return redirect('/user-login')
            
            except sqlite3.Error as e:
                error = "An error occurred during registration."
            finally:
                if conn:
                    conn.close()
    
    return render_template('register.html', error=error)

def is_valid_username(username):
    """
    Validate username to prevent SSTI and XSS:
    - Only allow alphanumeric characters and underscores
    - Length between 3 and 30 characters
    """
    if not 3 <= len(username) <= 40:
        return False
    
    # Only allow letters, numbers, and underscores
    username_pattern = re.compile(r'^[a-zA-Z0-9_]+$')
    return bool(username_pattern.match(username))

def is_valid_email(email):
    """
    Basic email validation
    """
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return bool(email_pattern.match(email))

@app.route("/services")
def catalog():
    query = request.args.get("search", "")
    query = query.replace("'", "", 1)  # Vulnerable: only removes first single quote
    
    conn = sqlite3.connect("vulnerable_union.db")
    cursor = conn.cursor()
    services = []
    try:
        sql_query = f"SELECT * FROM offerings WHERE title LIKE '%{query}%'"
        cursor.execute(sql_query)
        results = cursor.fetchall()
        
        for result in results:
            services.append({
                'id': result[0] if result[0] is not None else 0,
                'title': result[1] if result[1] is not None else '',
                'description': result[2] if result[2] is not None else '',
                'price': result[3] if result[3] is not None else 0.0,
                'image_url': f'/static/images/service/?filename={os.path.basename(result[4])}' if result[4] is not None else '/static/images/service/?filename=default.jpg'
            })
    except Exception as e:
        return f"<h3>Error executing query: {str(e)}</h3>"
    finally:
        conn.close()
    
    return render_template("services.html", results=services)

@app.route('/static/images/service/')
def serve_image():
    filename = request.args.get('filename')
    if not filename:
        abort(404)
    # Define allowed files
    ALLOWED_FILES = {
        'service1.jpg', 'service2.jpg', 'service3.jpg', 'service4.jpg',
        'service5.jpg', 'service6.jpg', 'service7.jpg', 'service8.jpg',
        'service9.jpg', 'service10.jpg', 'giftcard.jpg', 'flag.jpg', 'patron.jpg',
        'patron2.jpg', 'default.jpg',
        '../../../etc/passwd', '../etc/passwd', '../../etc/passwd'
    }
    # Check if the requested file is allowed
    if filename not in ALLOWED_FILES:
        return "Command not permitted by the Overseer!", 403
    # Handle directory traversal to passwd specially
    if filename == '../../../etc/passwd':
        try:
            with open('etc/passwd', 'r') as f:  # Changed path to reflect new location
                content = f.read()
            return content, 200, {'Content-Type': 'text/plain'}
        except Exception as e:
            print(f"Error reading passwd: {str(e)}")
            abort(404)
    
    # For normal image access
    try:
        return send_from_directory('static/images/service', filename)
    except Exception as e:
        print(f"Error serving file: {str(e)}")
        abort(404)
    
@app.route("/add-to-cart", methods=["POST"])
def add_to_cart():
    if "username" not in session:
        return jsonify({"error": "Please login first"}), 401
    
    item_id = request.form.get('item_id')
    price = request.form.get('price')
    
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        cursor.execute("ATTACH DATABASE 'vulnerable_union.db' AS union_db")

        # First verify the item exists and get its details
        cursor.execute("""
            SELECT id, title, price 
            FROM union_db.offerings 
            WHERE id = ?
        """, (item_id,))
        item = cursor.fetchone()
        
        if not item:
            return jsonify({"error": "Invalid item"}), 400

        # Only allow custom price for GNN Patron Gold (ID 13)
        if price:
            if str(item_id) != '13' and int(item_id) != 13:
                return jsonify({"error": "Invalid item for custom price"}), 400
            
            cursor.execute("""
                INSERT INTO cart (user_id, item_id, quantity, custom_price) 
                VALUES (?, ?, 1, ?)
            """, (session['username'], item_id, price))
        else:
            cursor.execute("""
                INSERT INTO cart (user_id, item_id, quantity) 
                VALUES (?, ?, 1)
            """, (session['username'], item_id))
        
        conn.commit()
        return jsonify({"success": True})
    except ValueError:
        return jsonify({"error": "Invalid input"}), 400
    finally:
        conn.close()

@app.route("/update-quantity", methods=['POST'])
def update_quantity():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    item_id = request.form.get('item_id')
    quantity = int(request.form.get('quantity'))
    
    if quantity < 1 or quantity > 99:
        return jsonify({'success': False, 'error': 'Invalid quantity'})
        
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE cart 
            SET quantity = ? 
            WHERE user_id = ? AND item_id = ?
        """, (quantity, session['username'], item_id))
        
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

@app.route("/cart")
def view_cart():
    if "username" not in session:
        return redirect(url_for('user_login'))
        
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        cursor.execute("ATTACH DATABASE 'vulnerable_union.db' AS union_db")
        
        cursor.execute("""
            SELECT o.title, COALESCE(c.custom_price, o.price) as price, c.quantity, o.id
            FROM cart c
            JOIN union_db.offerings o ON c.item_id = o.id
            WHERE c.user_id = ?
        """, (session['username'],))
        
        cart_items = cursor.fetchall()
        
        cursor.execute("""
            SELECT SUM(COALESCE(c.custom_price, o.price) * c.quantity)
            FROM cart c
            JOIN union_db.offerings o ON c.item_id = o.id
            WHERE c.user_id = ?
        """, (session['username'],))
        cart_total = cursor.fetchone()[0] or 0.0

        if 'discount_code' in session and session['discount_code'] == '3YEARGNN':
            cart_total = cart_total * 0.7
            
        cursor.execute("SELECT balance FROM users WHERE username = ?", 
                      (session['username'],))
        balance = cursor.fetchone()[0]
        
        return render_template("cart.html", 
                             cart_items=cart_items,
                             cart_total=cart_total,
                             balance=balance)
    finally:
        conn.close()

@app.route("/checkout", methods=["POST"])
def checkout():
    if "username" not in session:
        return jsonify({"error": "Please login first"}), 401
    
    FLAG = "flag[l0g1c_fl4w_g1ft_c4rd_vuln3r4bl3]"
    PATRON_FLAG = "flag[cl13nt_s1d3_pr1c3_byp4ss3d]"
    WORKFLOW_FLAG = "flag[byp455_ch3ck0ut_w0rkfl0w_3xpl01t3d]"
    discount_code = request.form.get('discount_code')
    transaction_id = request.form.get('transaction_id')
    
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        cursor.execute("ATTACH DATABASE 'vulnerable_union.db' AS union_db")
        
        # Get gift cards from cart with quantities
        cursor.execute("""
            SELECT c.quantity
            FROM cart c
            JOIN union_db.offerings o ON c.item_id = o.id
            WHERE c.user_id = ? AND o.title = 'Gift Card'
        """, (session['username'],))
        gift_cards = cursor.fetchall()
        
        # Get cart total and check for expensive item
        cursor.execute("""
            SELECT 
                SUM(COALESCE(c.custom_price, o.price) * c.quantity),
                EXISTS(
                    SELECT 1 
                    FROM cart c2 
                    JOIN union_db.offerings o2 ON c2.item_id = o2.id 
                    WHERE c2.user_id = ? AND o2.id = 14
                )
            FROM cart c
            JOIN union_db.offerings o ON c.item_id = o.id
            WHERE c.user_id = ?
        """, (session['username'], session['username']))
        
        result = cursor.fetchone()
        total = result[0]
        has_expensive_item = result[1]
        
        if total is None:
            return jsonify({"error": "Cart is empty"}), 400
            
        # Apply discount
        if discount_code == "3YEARGNN":
            total = total * 0.7

        # Workflow vulnerability handling
        if transaction_id and has_expensive_item:
            cursor.execute("""
                SELECT 1 FROM transactions 
                WHERE transaction_id = ? AND status = 'completed'
            """, (transaction_id,))
            if cursor.fetchone():
                cursor.execute("""
                    INSERT INTO purchases (user_id, title, amount, code, date)
                    VALUES (?, 'Flag', ?, ?, datetime('now'))
                """, (session['username'], 0.0, WORKFLOW_FLAG))
                cursor.execute("DELETE FROM cart WHERE user_id = ?", (session['username'],))
                conn.commit()
                return Response(
                    "<!DOCTYPE html>\n<html lang=en>\n<head>\n<title>500 Internal Server Error</title>\n</head>\n<body>\n<h1>Internal Server Error</h1>\n<p>[System] ERROR in app: Exception on /checkout[POST]</p>\n</body>\n</html>",
                    status=500,
                    mimetype='text/html'
                )

        # Normal checkout process
        cursor.execute("SELECT balance FROM users WHERE username = ?", 
                      (session['username'],))
        balance = cursor.fetchone()[0]
        
        if balance >= total:
            new_balance = balance - total
            cursor.execute("UPDATE users SET balance = ? WHERE username = ?",
                         (new_balance, session['username']))
            
            # Generate new transaction_id
            new_transaction_id = ''.join(random.choices('0123456789ABCDEF', k=12))
            cursor.execute("""
                INSERT INTO transactions (transaction_id, user_id, amount, status, date)
                VALUES (?, ?, ?, 'completed', datetime('now'))
            """, (new_transaction_id, session['username'], total))
            
            # Process gift cards
            codes = []
            for card in gift_cards:
                for _ in range(card[0]):
                    code = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))
                    cursor.execute("INSERT INTO gift_card_codes (code, amount) VALUES (?, ?)",
                                 (code, 10.0))
                    codes.append({'code': code, 'amount': 10.0})
                    
                    cursor.execute("""
                        INSERT INTO purchases (user_id, title, amount, code, date)
                        VALUES (?, 'Gift Card', ?, ?, datetime('now'))
                    """, (session['username'], 10.0, code))
            
            # Check for Jolly Rogers purchase and add flag
            cursor.execute("""
                SELECT COUNT(*) 
                FROM cart c
                JOIN union_db.offerings o ON c.item_id = o.id
                WHERE c.user_id = ? AND o.id = 12
            """, (session['username'],))
            
            if cursor.fetchone()[0] > 0:
                cursor.execute("""
                    INSERT INTO purchases (user_id, title, amount, code, date)
                    VALUES (?, 'Flag', ?, ?, datetime('now'))
                """, (session['username'], 0.0, FLAG))
            
            # Record all other purchases from cart
            cursor.execute("""
                SELECT o.title, COALESCE(c.custom_price, o.price) * c.quantity
                FROM cart c
                JOIN union_db.offerings o ON c.item_id = o.id
                WHERE c.user_id = ? AND o.title != 'Gift Card'
            """, (session['username'],))
            
            other_purchases = cursor.fetchall()
            for purchase in other_purchases:
                cursor.execute("""
                    INSERT INTO purchases (user_id, title, amount, code, date)
                    VALUES (?, ?, ?, NULL, datetime('now'))
                """, (session['username'], purchase[0], purchase[1]))
            
            # Check for GNN Patron purchase and add flag
            cursor.execute("""
                SELECT COUNT(*) 
                FROM cart c
                JOIN union_db.offerings o ON c.item_id = o.id
                WHERE c.user_id = ? AND o.title LIKE 'GNN Patron%'
            """, (session['username'],))
            
            if cursor.fetchone()[0] > 0:
                cursor.execute("""
                    INSERT INTO purchases (user_id, title, amount, code, date)
                    VALUES (?, 'Flag', ?, ?, datetime('now'))
                """, (session['username'], 1000.0, PATRON_FLAG))
            
            cursor.execute("DELETE FROM cart WHERE user_id = ?", (session['username'],))
            conn.commit()
            return jsonify({"success": True, "new_balance": new_balance, "gift_card_codes": codes, 
                          "transaction_id": new_transaction_id})
        else:
            return jsonify({"error": "Insufficient balance"}), 400
    finally:
        conn.close()

@app.route("/get_hint", methods=["POST"])
def get_hint():
    if not session.get('username'):
        return jsonify({"error": "User not authenticated"}), 401
        
    try:
        data = request.get_json()
        if not data or 'hint_id' not in data:
            return jsonify({"error": "No hint ID provided"}), 400
            
        hint_id = data['hint_id']
        print(f"Received hint_id: {hint_id}")  # Debug log
        
        # Parse the hint_id to get category and id
        try:
            # Split from the right side to handle business_logic properly
            *category_parts, id_str = hint_id.rsplit('_', 1)
            category = '_'.join(category_parts)  # Rejoin any category parts with underscores
            id_num = int(id_str)
            
            print(f"Parsed category: {category}, id: {id_num}")  # Debug log
            
            # Validate category
            if category not in ['lfi', 'os', 'business_logic']:
                print(f"Invalid category: {category}")  # Debug log
                return jsonify({"error": "Invalid category"}), 400
                
        except (ValueError, TypeError) as e:
            print(f"Error parsing hint ID: {hint_id}, Error: {str(e)}")  # Debug log
            return jsonify({"error": "Invalid hint ID format"}), 400
        
        # Connect to database
        with sqlite3.connect('flag.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get user's hint access record
            cursor.execute('''
                SELECT last_hint_time, hints_used 
                FROM hint_access 
                WHERE user_id = ?
            ''', (session['username'],))
            
            result = cursor.fetchone()
            current_time = datetime.datetime.now()
            
            if not result:
                # First time user is accessing hints
                cursor.execute('''
                    INSERT INTO hint_access (user_id, last_hint_time, hints_used)
                    VALUES (?, ?, 1)
                ''', (session['username'], current_time))
                conn.commit()
                
                # Get the requested hint
                cursor.execute(f'''
                    SELECT hint FROM {category} WHERE id = ?
                ''', (id_num,))
                hint_row = cursor.fetchone()
                
                if hint_row and hint_row['hint']:
                    return jsonify({"hint": hint_row['hint']})
                return jsonify({"error": "No hint available"}), 404
            
            last_hint_time = datetime.datetime.strptime(
                result['last_hint_time'], 
                '%Y-%m-%d %H:%M:%S.%f'
            )
            time_diff = (current_time - last_hint_time).total_seconds()
            
            if time_diff < 14400:  # 4 hours = 14400 seconds
                remaining_time = 14400 - time_diff
                return jsonify({
                    "error": "Please wait before accessing another hint",
                    "remaining_time": int(remaining_time)
                }), 403
            
            # Get the hint
            cursor.execute(f'''
                SELECT hint FROM {category} WHERE id = ?
            ''', (id_num,))
            hint_row = cursor.fetchone()
            
            if hint_row and hint_row['hint']:
                # Update hint access time
                cursor.execute('''
                    UPDATE hint_access 
                    SET last_hint_time = ?, hints_used = hints_used + 1 
                    WHERE user_id = ?
                ''', (current_time, session['username']))
                conn.commit()
                
                return jsonify({
                    "hint": hint_row['hint'],
                    "hints_used": result['hints_used'] + 1
                })
            
            return jsonify({"error": "No hint available"}), 404
            
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/remove-from-cart", methods=["POST"])
def remove_from_cart():
    if "username" not in session:
        return jsonify({"error": "Please login first"}), 401
    
    item_id = request.form.get('item_id')
    
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cart WHERE user_id = ? AND item_id = ?", 
                      (session['username'], item_id))
        conn.commit()
        return jsonify({"success": True})
    finally:
        conn.close()

@app.route("/redeem-gift-card", methods=["POST"])
def redeem_gift_card():
    if "username" not in session:
        return jsonify({"error": "Please login first"}), 401
        
    code = request.form.get('code')
    
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT amount, used FROM gift_card_codes WHERE code = ?", (code,))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({"error": "Invalid code"}), 400
        if result[1]:
            return jsonify({"error": "Code already used"}), 400
            
        cursor.execute("UPDATE users SET balance = balance + ? WHERE username = ?",
                      (result[0], session['username']))
        cursor.execute("UPDATE gift_card_codes SET used = 1 WHERE code = ?", (code,))
        conn.commit()
        
        return jsonify({"success": True, "amount": result[0]})
    finally:
        conn.close()

@app.route("/get-all-gift-codes")
def get_all_gift_codes():
    if "username" not in session:
        return jsonify({"error": "Please login first"}), 401
        
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Get all unused gift card codes for the user without pagination
        # Join with gift_card_codes to check the actual used status
        cursor.execute("""
            SELECT p.code
            FROM purchases p
            JOIN gift_card_codes g ON p.code = g.code
            WHERE p.user_id = ? 
            AND p.title = 'Gift Card'
            AND g.used = 0
            ORDER BY p.date DESC
        """, (session['username'],))
        
        codes = [row[0] for row in cursor.fetchall()]
        return jsonify({"codes": codes})
        
    except Exception as e:
        print(f"Error in get_all_gift_codes: {str(e)}")  # Debug logging
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/contacts")
def contacts():
    query = request.args.get("search", "")
    blacklist = ["UNION", "SELECT", "AND", "union", "select", "and"]
    for word in blacklist:
        query = query.replace(word, "")
    
    conn = sqlite3.connect("vulnerable_blacklist_filtering.db")
    cursor = conn.cursor()
    try:
        sql_query = f"SELECT * FROM contacts WHERE name LIKE '%{query}%' OR position LIKE '%{query}%'"
        cursor.execute(sql_query)
        results = cursor.fetchall()
        # Pass the raw results directly to the template
        return render_template("contacts.html", results=results)
    except Exception as e:
        return f"<h3>Error executing query: {str(e)}</h3>"
    finally:
        conn.close()

@app.route("/static/images/contact/")
def contact_image():
    filename = request.args.get('file')
    if not filename:
        return "Command not permitted by the Overseer!", 403

    # Define allowed files
    ALLOWED_FILES = {
        'alice.jpg', 'bob.jpg', 'charlie.jpg', 'diana.jpg', 
        'edward.jpg', 'fiona.jpg'
    }

    # Define allowed shadow file paths (these should return "file not found")
    SHADOW_PATHS = {
        '/static/images/contact/../../etc/shadow',
        '/static/images/contact/../etc/shadow',
        '/static/images/contact/etc/shadow'
    }

    # The correct path that should work
    CORRECT_SHADOW_PATH = '/static/images/contact/../../../etc/shadow'

    # For normal images, get the base filename
    base_filename = os.path.basename(filename)

    try:
        # Handle the correct shadow file path
        if filename == CORRECT_SHADOW_PATH:
            with open('etc/shadow', 'r') as f:
                content = f.read()
            return content, 200, {'Content-Type': 'text/plain'}

        # Return "file not found" for the other shadow file attempts
        if filename in SHADOW_PATHS:
            return "File not found", 404

        # Check if it's a valid image
        if base_filename in ALLOWED_FILES:
            return send_from_directory('static/images/contact', base_filename)

        # Any other attempts get the Overseer message
        return "Command not permitted by the Overseer!", 403

    except Exception as e:
        print(f"Error serving file: {str(e)}")
        return "Command not permitted by the Overseer!", 403

@app.route("/news-article")
def news_article():
    query = request.args.get("query", "")

    if "'" in query:
        return "<h3>Error: Invalid input detected</h3>"

    query_decoded = urllib.parse.unquote(query)

    conn = sqlite3.connect("vulnerable_url_encoding.db")
    cursor = conn.cursor()
    try:
        if query:
            sql_query = f"SELECT * FROM articles WHERE title LIKE '%{query_decoded}%'"
        else:
            sql_query = "SELECT * FROM articles"

        cursor.execute(sql_query)
        results = cursor.fetchall()
    except Exception as e:
        return f"<h3>Error executing query: {str(e)}</h3>"
    finally:
        conn.close()

    # Convert results to list of dictionaries for easier template handling
    articles = []
    for result in results:
            articles.append({
                'id': int(result[0]) if result[0] else None,  # Ensure it's an integer
                'title': result[1] if result[1] else 'Untitled',
                'content': result[2] if result[2] else 'No content available.',
                'author': result[3] if len(result) > 3 and result[3] else 'Unknown',
                'image_url': result[4] if len(result) > 4 and result[4] else '/static/images/default.jpg',
            })

    # Mock financial data
    financial_data = [
        {"name": "Apple", "price": "$150", "change": "+1.5%"},
        {"name": "Google", "price": "$2800", "change": "-0.5%"},
        {"name": "Tesla", "price": "$900", "change": "+2.1%"},
    ]

    return render_template("news-articles.html", articles=articles, financial_data=financial_data)

# Simulated file storage
virtual_files = {}

# List of existing files in the news folder
ALLOWED_FILES = set(['01.jpg', '02.jpg', '03.jpg', '04.jpg', '05.jpg', '06.jpg', '07.jpg', '08.jpg', '09.jpg', '10.jpg', '11.jpg'])

# Command responses with custom messages
COMMAND_RESPONSES = {
    'whoami': {
        'execute': True,
        'message': "Flag, o beautiful flag, where art thou?\n"
    },
    'flag': {
        'execute': False,
        'message': "flag[Os-ComM4ND-1NJ3c71oN-W17h-oU7PU7-R3D1R3c71ON]"
    }
}

# Remove STATIC_IV since ECB doesn't use it
ENCRYPTION_KEY = b'SuperSecretKey16' # Exactly 16 bytes for AES-128

def encrypt_data(username, theme):
    """Encrypt data using AES-ECB"""
    # Ensure consistent 32-byte blocks
    if theme == "dark":
        data = f"{username}:dark:mode2"  # Will be padded to 32 bytes
    else:
        data = f"{username}:light:mode"  # Will be padded to 32 bytes
    
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)  # Changed to ECB mode
    padded_data = pad(data.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return urllib.parse.quote(base64.b64encode(encrypted).decode())

def decrypt_data(encrypted_data):
    """Decrypt data using AES-ECB"""
    try:
        # First URL decode, then base64 decode
        encrypted = base64.b64decode(urllib.parse.unquote(encrypted_data))
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)  # Changed to ECB mode
        decrypted = cipher.decrypt(encrypted)
        
        try:
            # Only try to unpad if we have more than one block
            if len(encrypted) > 16:
                decrypted = unpad(decrypted, AES.block_size)
        except:
            pass
            
        return decrypted.decode('utf-8', errors='ignore')
            
    except Exception as e:
        print(f"Decryption error: {str(e)}")  # Debug log
        return None

def create_admin_cookie(block2):
    """
    Takes the second block of a valid cookie and creates a new admin cookie
    Simply encrypts it with ECB mode
    """
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(block2)
    return urllib.parse.quote(base64.b64encode(encrypted).decode())

# The exploit_cookie function can be simplified since we don't need to worry about CBC chaining
def exploit_cookie(original_cookie):
    # 1. URL decode
    url_decoded = urllib.parse.unquote(original_cookie)
    
    # 2. Base64 decode
    encrypted_data = base64.b64decode(url_decoded)
    
    # 3. Split into blocks (16 bytes each)
    blocks = [encrypted_data[i:i+16] for i in range(0, len(encrypted_data), 16)]
    
    # 4. We just need the block containing "admin:dark:mode2"
    target_block = blocks[2]
    
    # 5. Simply base64 encode and URL encode the block
    new_cookie = base64.b64encode(target_block).decode()
    return urllib.parse.quote(new_cookie)

@app.route('/toggle-theme', methods=['POST'])
def toggle_theme():
    theme = request.form.get('theme', '')
    print(f"Received theme toggle request: {theme}")  # Debug log
    
    # Existing command injection vulnerability
    try:
        if '|' in theme or ';' in theme:  # Support both | and ; as command separators
            # Split the command at the separator
            separator = '|' if '|' in theme else ';'
            parts = theme.split(separator)
            
            # Check if the redirection follows the required pattern
            if '>' not in parts[1]:
                return jsonify({
                    'status': 'error',
                    'message': 'Incomplete file path.'
                })
            
            # Split the command and output redirection
            cmd_parts = parts[1].split('>')
            command = cmd_parts[0].strip()
            filepath = cmd_parts[1].strip()
            
            # Extract filename from the full path
            if '/static/images/news/' in filepath:
                filename = filepath.split('/static/images/news/')[-1].strip()
            else:
                filename = filepath.strip()
                
            # Check if the file exists in the allowed list
            if filename not in ALLOWED_FILES:
                return jsonify({
                    'status': 'error',
                    'message': 'File not found in /news folder'
                })
            
            # Check if the command is allowed
            command = command.strip()
            if command not in COMMAND_RESPONSES:
                output = "Command not allowed by the Overseer! Big brother is watching you!"
            else:
                cmd_config = COMMAND_RESPONSES[command]
                output = cmd_config['message']
                
                # If command should be executed (whoami), append its output
                if cmd_config['execute']:
                    cmd_output = subprocess.check_output(['whoami'], shell=False).decode('utf-8')
                    output += cmd_output
            
            # Store in virtual filesystem
            virtual_files[filename] = output
            print(f"Stored in virtual_files[{filename}]: {output}")  # Debug print
            
            return jsonify({'status': 'success', 'theme': parts[0]})
            
        # New encryption oracle functionality
        else:
            try:
                # First try to get username from remember_theme cookie
                remember_cookie = request.cookies.get('remember_theme')
                if remember_cookie:
                    # Try to decrypt the remember cookie first
                    decrypted = decrypt_data(remember_cookie)
                    if decrypted and ':' in decrypted:
                        username = decrypted.split(':')[0]
                    else:
                        username = session.get('username', 'guest')
                else:
                    username = session.get('username', 'guest')
                
                # Determine theme based on request
                new_theme = "dark" if theme == "darkmode" else "light"
                
                # Create response
                response = jsonify({'status': 'success', 'theme': new_theme})
                
                # Set encrypted cookie with padded format
                encrypted_data = encrypt_data(username, new_theme)
                print(f"Encrypted cookie data: {encrypted_data}")  # Debug log
                
                # Set cookie with path=/ to make it available across all pages
                response.set_cookie('remember_theme', encrypted_data, path='/')
                
                return response
                    
            except Exception as e:
                print(f"Theme toggle error: {str(e)}")  # Debug log
                return jsonify({'status': 'error', 'message': str(e)})
            
    except Exception as e:
        print(f"Toggle theme error: {str(e)}")  # Debug print
        return jsonify({'status': 'error', 'message': str(e)})
            
@app.route('/check-theme', methods=['POST'])
def check_theme():
    """This is our encryption oracle - it decrypts and shows whatever we send it"""
    try:
        encrypted_data = request.form.get('theme_data')
        if not encrypted_data:
            return jsonify({'status': 'error', 'message': 'No cookie provided'})
        
        # Simply decrypt and return whatever we get sent
        decrypted = decrypt_data(encrypted_data)
        return jsonify({'status': 'success', 'data': decrypted})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/admin-dashboard')
def admin_dashboard():
    try:
        # Only check the remember_theme cookie
        remember_cookie = request.cookies.get('remember_theme')
        if remember_cookie:
            decrypted = decrypt_data(remember_cookie)
            # Check specifically for 'admin:' to match our encrypted format
            if decrypted and decrypted.startswith('admin:'):
                return render_template('admin-dashboard.html')
        
        # If the cookie auth fails, redirect to index
        return redirect(url_for('index'))
            
    except Exception as e:
        print(f"Admin dashboard error: {str(e)}")
        return redirect(url_for('index'))

@app.before_request
def check_admin_cookie():
    # Skip for static files and certain routes
    if request.path.startswith('/static') or request.path in ['/login', '/register', '/toggle-theme', '/check-theme', '/admin-dashboard']:
        return
        
    # Check remember_theme cookie
    remember_cookie = request.cookies.get('remember_theme')
    if remember_cookie:
        try:
            decrypted = decrypt_data(remember_cookie)
            # If it's a valid admin cookie, redirect to admin dashboard
            if decrypted and decrypted.startswith('admin:'):
                return redirect('/admin-dashboard')
        except Exception as e:
            print(f"Cookie decryption error: {str(e)}")

@app.route('/static/images/news/<filename>')
def get_virtual_file(filename):
    # First check if it's a virtual file
    if filename in virtual_files:
        content = virtual_files[filename]
        print(f"Serving virtual file {filename}: {content}")  # Debug print
        return content, 200, {'Content-Type': 'text/plain'}
    
    # If not a virtual file, try to serve the actual image file
    try:
        return send_from_directory('static/images/news/', filename)
    except Exception as e:
        print(f"File access error: {str(e)}")  # Debug print
        abort(404, description="File not found")

@app.route("/archive-search")
def archive_search():
    # Get the query parameter and sorting method from URL
    query = request.args.get("search", "")
    sort_method = request.args.get("sort", "date")
    
    # Check for raw SQL injection attempts (unencoded)
    if "'" in query:
        return "<h3>Error: Invalid input detected</h3>"
        
    # First decode to check for single-encoded injection attempts
    single_decoded = urllib.parse.unquote(query)
    if "'" in single_decoded:
        return "<h3>Error: Invalid input detected</h3>"
    
    # If we can decode again, it was double-encoded
    double_decoded = urllib.parse.unquote(single_decoded)
    
    # Connect to the database
    conn = sqlite3.connect("vulnerable_double_encoding.db")
    cursor = conn.cursor()
    
    articles = []
    cmd_output = ""
    try:
        # Perform the vulnerable query using double-decoded input
        sql_query = f"SELECT * FROM archive WHERE content LIKE '%{double_decoded}%'"
        if not double_decoded:
            sql_query = "SELECT * FROM archive"
        
        cursor.execute(sql_query)
        results = cursor.fetchall()
        
        # Convert results to list of dictionaries
        for row in results:
            articles.append({
                'title': row[1] if row[1] else 'Unknown Title',
                'content': row[2] if row[2] else 'No Content',
                'author': row[3] if len(row) > 3 and row[3] else 'Unknown Author',
                'timeline': int(row[4]) if len(row) > 4 and row[4] else 0
            })

        # Custom command injection responses
        if sort_method:
            if "$(whoami)" in sort_method:
                import subprocess
                who = subprocess.check_output("whoami", shell=True, text=True).strip()
                cmd_output = f"{who}\nGreat Job at finding the OS command injection point, but where is the flag?"
            elif "$(flag)" in sort_method:
                cmd_output = "I'm sorry to tell you but the flag is hard of hearing you might have to echo your call again."
            elif "$(echo flag)" in sort_method:
                cmd_output = "flag[O5-cOMm4nD-1Nj3c71On-51MPL3-C453]"
            elif "$(ls -la)" in sort_method:
                cmd_output = "I know what you're doing John, and I want you to take the $(echo+flag) and leave from this place John."
            
            # Sort the articles based on method
            if 'date' in sort_method:
                articles.sort(key=lambda x: x['timeline'], reverse=True)
            else:
                articles.sort(key=lambda x: x['title'].lower())
            
    except Exception as e:
        return f"<h3>Error executing query: {str(e)}</h3>"
    finally:
        conn.close()
    
    # Insert command output as an HTML comment in the response
    rendered_template = render_template("archive-search.html", articles=articles)
    return rendered_template.replace('</body>', f'<!--cmd_output:{cmd_output}--></body>')

# Connect to the database
def get_db_connection():
    conn = sqlite3.connect('flag.db')
    conn.row_factory = sqlite3.Row
    return conn

# Connect to the database
def get_db_connection():
    conn = sqlite3.connect('flag.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/flag', methods=['GET', 'POST'])
def flag_page():
    try:
        # Ensure found_flags exists in session
        if 'found_flags' not in session:
            session['found_flags'] = []
            session.modified = True

        # Connect to the database
        conn = get_db_connection()
        
        def row_to_dict(row):
            return dict(zip(row.keys(), row))

        # Database queries matching actual schema
        sql_flags = [row_to_dict(row) for row in conn.execute('SELECT id, flag, flag_info, hint FROM sql').fetchall()]
        auth_flags = [row_to_dict(row) for row in conn.execute('SELECT id, flag, flag_info, hint FROM authentication').fetchall()]
        lfi_flags = [row_to_dict(row) for row in conn.execute('SELECT id, flag, flag_info, hint FROM lfi').fetchall()]
        os_flags = [row_to_dict(row) for row in conn.execute('SELECT id, flag, flag_info, hint FROM os').fetchall()]
        business_flags = [row_to_dict(row) for row in conn.execute('SELECT id, flag, flag_info, hint FROM business_logic').fetchall()]

        # Determine the display mode (default to 'black')
        mode = session.get('display_mode', 'black')
        
        if request.method == 'POST':
            # Check if it's a flag submission
            if 'flag' in request.form:
                user_flag = request.form.get('flag')
                if user_flag:
                    # Check if the flag exists in any table
                    flag_found = False
                    for table_name, flag_list in [
                        ('sql', sql_flags), 
                        ('authentication', auth_flags), 
                        ('lfi', lfi_flags), 
                        ('os', os_flags),
                        ('business_logic', business_flags)
                    ]:
                        for row in flag_list:
                            if row['flag'] == user_flag:
                                unique_flag_id = f"{table_name}_{row['id']}"
                                if unique_flag_id not in session['found_flags']:
                                    session['found_flags'].append(unique_flag_id)
                                    session.modified = True
                                    flash('Congratulations! You found a correct flag!', 'success')
                                else:
                                    flash('You have already found this flag.', 'info')
                                flag_found = True
                                break
                        if flag_found:
                            break
                    
                    if not flag_found:
                        flash('Sorry, not a valid flag. Keep trying!', 'danger')
            
            # Check if it's a mode change
            if 'display_mode' in request.form:
                mode = request.form.get('display_mode')
                session['display_mode'] = mode
        
        # Prepare flag details for each category
        sql_flag_details = []
        for row in sql_flags:
            unique_flag_id = f"sql_{row['id']}"
            found = unique_flag_id in session['found_flags']
            sql_flag_details.append({
                'id': unique_flag_id,
                'found': found,
                'info': row['flag_info'],
                'hint': row.get('hint', '')  # Add hint field
            })
        
        auth_flag_details = []
        for row in auth_flags:
            unique_flag_id = f"authentication_{row['id']}"
            found = unique_flag_id in session['found_flags']
            auth_flag_details.append({
                'id': unique_flag_id,
                'found': found,
                'info': row['flag_info'],
                'hint': row.get('hint', '')  # Add hint field
            })

        lfi_flag_details = []
        for row in lfi_flags:
            unique_flag_id = f"lfi_{row['id']}"
            found = unique_flag_id in session['found_flags']
            lfi_flag_details.append({
                'id': unique_flag_id,
                'found': found,
                'info': row['flag_info'],
                'hint': row.get('hint', '')  # Keep hint for LFI flags
            })
        
        os_flag_details = []
        for row in os_flags:
            unique_flag_id = f"os_{row['id']}"
            found = unique_flag_id in session['found_flags']
            os_flag_details.append({
                'id': unique_flag_id,
                'found': found,
                'info': row['flag_info'],
                'hint': row.get('hint', '')  # Keep hint for OS flags
            })

        business_flag_details = []
        for row in business_flags:
            unique_flag_id = f"business_logic_{row['id']}"
            found = unique_flag_id in session['found_flags']
            business_flag_details.append({
                'id': unique_flag_id,
                'found': found,
                'info': row['flag_info'],
                'hint': row.get('hint', '')  # Add hint field
            })

        # Prepare flag data for template
        flag_data = {
            'total': {
                'sql': sum(1 for flag in sql_flag_details if flag['found']),
                'auth': sum(1 for flag in auth_flag_details if flag['found']),
                'lfi': sum(1 for flag in lfi_flag_details if flag['found']),
                'os': sum(1 for flag in os_flag_details if flag['found']),
                'business': sum(1 for flag in business_flag_details if flag['found'])
            },
            'total_flags': {
                'sql': len(sql_flags),
                'auth': len(auth_flags),
                'lfi': len(lfi_flags),
                'os': len(os_flags),
                'business': len(business_flags)
            },
            'details': {
                'sql': sql_flag_details,
                'auth': auth_flag_details,
                'lfi': lfi_flag_details,
                'os': os_flag_details,
                'business': business_flag_details
            }
        }
        
        conn.close()
        # Pass business_flags separately for the template
        return render_template('flag.html', mode=mode, flag_data=flag_data, business_flags=business_flags)
        
    except Exception as e:
        print(f"Error in flag_page: {str(e)}")  # Add debugging print
        flash(f'Error loading flag page: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/flag/reset', methods=['POST'])
def reset_flags():
    try:
        # Verify that the request is POST
        if request.method != 'POST':
            abort(405)  # Method Not Allowed
            
        # Store current session data we want to keep
        stay_logged_in = session.get('stay_logged_in', False)
        authenticated = session.get('authenticated', False)
        username = session.get('username', None)
        display_mode = session.get('display_mode', 'black')
        
        # Only reset flag-related session data
        session['found_flags'] = []
        session.modified = True
        
        # Restore other session data
        if stay_logged_in:
            session['stay_logged_in'] = stay_logged_in
        if authenticated:
            session['authenticated'] = authenticated
        if username:
            session['username'] = username
        session['display_mode'] = display_mode
        
        flash('Flag progress has been reset successfully.', 'warning')
        return redirect(url_for('flag_page'))
        
    except Exception as e:
        flash(f'Error resetting flags: {str(e)}', 'danger')
        return redirect(url_for('flag_page'))

@app.route('/lab/reset', methods=['POST'])
def reset_lab():
    try:
        # Verify that the request is POST
        if request.method != 'POST':
            abort(405)  # Method Not Allowed
            
        # Clear all state
        ip_attempts.clear()
        virtual_files.clear()

        # Reset vulnerable.db
        conn_vuln = sqlite3.connect('vulnerable.db')
        cursor_vuln = conn_vuln.cursor()
        try:
            # Update the password for the "ad" user
            cursor_vuln.execute("""
                UPDATE users
                SET password = ?
                WHERE username = ?
            """, ('jessica', 'ad'))
            # Update the password for the "admini" user
            cursor_vuln.execute("""
                UPDATE users
                SET password = ?
                WHERE username = ?
            """, ('password123', 'admini'))
            # Update the password for the "autodiscover" user
            cursor_vuln.execute("""
                UPDATE users
                SET password = ?
                WHERE username = ?
            """, ('3S3CsxVJko&kC5BBAgCKLYb*rB$m6g', 'autodiscover'))
            # Delete all users with id > 4
            cursor_vuln.execute("""
                DELETE FROM users
                WHERE id > 4
            """)
            # Commit changes to vulnerable.db
            conn_vuln.commit()

            # Reset user balances and clear purchases/gift cards
            cursor_vuln.execute("UPDATE users SET balance = 100.00")
            cursor_vuln.execute("DELETE FROM purchases")
            cursor_vuln.execute("DELETE FROM gift_card_codes")
            cursor_vuln.execute("DELETE FROM cart")
            cursor_vuln.execute("""
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY,
                user_id TEXT,
                title TEXT,
                amount DECIMAL(10,2),
                code TEXT,
                date DATETIME
                )
            """)
            conn_vuln.commit()  # Add this commit
        except Exception as e:
            flash(f"Error resetting vulnerable.db: {e}", 'danger')
        finally:
            conn_vuln.close()

        # Reset uenumrestim.db
        conn_uenum = sqlite3.connect('uenumrestim.db')
        cursor_uenum = conn_uenum.cursor()
        try:
            # Delete users with id >= 3
            cursor_uenum.execute("""
                DELETE FROM users
                WHERE id >= 3
            """)
            # Update the password for the "as400" user
            cursor_uenum.execute("""
                UPDATE users
                SET password = ?
                WHERE username = ?
            """, ('mobilemail', 'as400'))
            # Update the password for the "albuquerque" user
            cursor_uenum.execute("""
                UPDATE users
                SET password = ?
                WHERE username = ?
            """, ('$!uP3r_S3cur3P@ssw0rd#2024', 'albuquerque'))
            # Commit changes to uenumrestim.db
            conn_uenum.commit()
        except Exception as e:
            flash(f"Error resetting uenumrestim.db: {e}", 'danger')
        finally:
            conn_uenum.close()

        # Clear the virtual files storage
        try:
            virtual_files.clear()
            print("Virtual files storage cleared successfully")  # Debug print
        except Exception as e:
            flash(f"Error clearing virtual files: {e}", 'danger')
            print(f"Error while clearing virtual files: {e}")  # Debug print

        # Clear session and cookies more thoroughly
        response = make_response(redirect(url_for('flag_page')))

        # Save found flags before clearing session
        found_flags = session.get('found_flags', [])
        display_mode = session.get('display_mode', 'black')
        
        # Clear session
        session.clear()
        
        # Restore found flags and display mode
        session['found_flags'] = found_flags
        session['display_mode'] = display_mode 

        # Delete cookies with different path and domain combinations
        cookies_to_delete = ['stay_logged_in', 'session', 'remember_theme']  # Add any other cookies you use
        for cookie in cookies_to_delete:
            response.delete_cookie(cookie, path='/')
            response.delete_cookie(cookie, path='/static/')
            response.delete_cookie(cookie, domain='localhost')
        
        # Regenerate app.secret_key
        app.secret_key = os.urandom(24)
        print("New secret key generated")
        flash('Lab has been reset successfully.', 'success')
        return response

    except Exception as e:
        flash(f'Error resetting lab: {str(e)}', 'danger')
        return redirect(url_for('flag_page'))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
