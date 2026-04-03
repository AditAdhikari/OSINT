import os
import socket
import json
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps

# Custom modules
from stats_utils import get_live_stats
from password_checker import check_password_strength
from auth_handler import register_user, login_user

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# File paths
DATA_PATH = os.path.join(BASE_DIR, 'data', 'breaches.json')
WHOIS_PATH = os.path.join(BASE_DIR, 'data', 'whois_registry.json')

# Load breach data safely
try:
    email_index, stats_data = get_live_stats(DATA_PATH)
except Exception as e:
    print("Error loading breach data:", e)
    email_index, stats_data = {}, {}

# =========================
# LOGIN REQUIRED DECORATOR
# =========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# =========================
# ROUTES
# =========================

@app.route('/')
def index():
    return render_template('index.html')


# =========================
# AUTH
# =========================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = login_user(request.form['email'], request.form['password'])
        if user:
            session['user'] = user
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials")
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        success = register_user(request.form['email'], request.form['password'])
        if success:
            flash("Registered successfully. Please login.")
            return redirect(url_for('login'))
        else:
            flash("User already exists")
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# =========================
# EMAIL BREACH CHECK
# =========================

@app.route('/check', methods=['POST'])
@login_required
def check_email():
    email = request.form['email'].lower()

    breaches = email_index.get(email, [])

    return render_template(
        'index.html',
        email=email,
        breaches=breaches,
        found=bool(breaches)
    )


# =========================
# PASSWORD CHECK
# =========================

@app.route('/password', methods=['GET', 'POST'])
@login_required
def password():
    result = None

    if request.method == 'POST':
        pwd = request.form['password']
        result = check_password_strength(pwd)

    return render_template('password_check.html', result=result)


# =========================
# WHOIS LOOKUP
# =========================

@app.route('/whois', methods=['GET', 'POST'])
@login_required
def whois():
    result = None

    if request.method == 'POST':
        domain = request.form['domain'].lower()

        try:
            with open(WHOIS_PATH, 'r') as f:
                data = json.load(f)

            result = data.get(domain, {"error": "Domain not found"})
        except Exception as e:
            result = {"error": str(e)}

    return render_template('whois.html', result=result)


# =========================
# DOMAIN → IP + IP INFO
# =========================

@app.route('/ip', methods=['GET', 'POST'])
@login_required
def ip_lookup():
    results = []

    if request.method == 'POST':
        domain = request.form['domain']

        try:
            ip = socket.gethostbyname(domain)

            # Get IP info
            try:
                res = requests.get(f"http://ip-api.com/json/{ip}").json()
                country = res.get("country", "Unknown")
                isp = res.get("isp", "Unknown")
            except:
                country = "Unknown"
                isp = "Unknown"

            results.append({
                "domain": domain,
                "ip": ip,
                "country": country,
                "isp": isp
            })

        except Exception as e:
            results.append({
                "domain": domain,
                "error": str(e)
            })

    return render_template('ip_lookup.html', results=results)


# =========================
# STATS
# =========================

@app.route('/stats')
@login_required
def stats():
    return render_template('stats.html', stats=stats_data)


# =========================
# RUN
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)