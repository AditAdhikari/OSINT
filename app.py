import os
import json
import socket
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps

from stats_utils import get_live_stats
from password_checker import check_password_strength
from auth_handler import register_user, login_user

app = Flask(__name__)
app.secret_key = "cyber_security_secret_key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_PATH = os.path.join(BASE_DIR, 'data', 'breaches.json')
WHOIS_PATH = os.path.join(BASE_DIR, 'data', 'whois_registry.json')

# Load data safely
email_index, stats_data = get_live_stats(DATA_PATH)

# 🔐 LOGIN REQUIRED
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("🔒 Please login first.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# 🏠 HOME
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    result, error, risk = [], None, None

    if request.method == "POST":
        email = (request.form.get("email") or "").lower().strip()
        result = email_index.get(email, [])

        if result:
            avg = sum([r.get("severity", 0) for r in result]) / len(result)
            if avg >= 8:
                risk = "🔴 CRITICAL"
            elif avg >= 5:
                risk = "🟠 MEDIUM"
            else:
                risk = "🟢 LOW"
        else:
            error = "✅ No breaches found."

    return render_template("index.html", result=result, error=error, risk=risk)


# 📊 STATS
@app.route("/stats")
@login_required
def stats_page():
    _, latest_stats = get_live_stats(DATA_PATH)
    return render_template("stats.html", stats=latest_stats)


# 🔑 PASSWORD CHECK
@app.route("/password-check", methods=["GET", "POST"])
@login_required
def password_page():
    strength = None

    if request.method == "POST":
        password = request.form.get("password")
        if password:
            strength = check_password_strength(password)

    return render_template("password_check.html", strength=strength)


# 🌐 WHOIS
@app.route('/whois', methods=['GET', 'POST'])
@login_required
def whois():
    result = None
    domain_query = ""

    if request.method == 'POST':
        domain_query = request.form.get('domain', '').strip().lower()
        domain_query = domain_query.replace("https://", "").replace("http://", "")
        domain_query = domain_query.replace("www.", "")
        domain_query = domain_query.split("/")[0]

        try:
            if os.path.exists(WHOIS_PATH):
                with open(WHOIS_PATH, 'r', encoding='utf-8') as f:
                    db = json.load(f)

                for key in db:
                    if key.strip().lower() == domain_query:
                        result = db[key]
                        break
            else:
                flash("❌ WHOIS database not found", "danger")

        except Exception as e:
            flash(f"❌ Error: {str(e)}", "danger")

    return render_template('whois.html', result=result, domain=domain_query)


# 🌍 IP LOOKUP (FIXED)
@app.route('/ip-lookup', methods=['GET', 'POST'])
@login_required
def ip_lookup():
    ips = []
    error = None
    domain = ""

    if request.method == "POST":
        domain = request.form.get("domain", "").strip()

        try:
            _, _, ipaddrlist = socket.gethostbyname_ex(domain)
            ips = ipaddrlist
        except Exception:
            error = "❌ Could not resolve domain."

    return render_template("ip_lookup.html", ips=ips, error=error, domain=domain)


# 👤 REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if 'user' in session:
        return redirect(url_for('index'))

    if request.method == "POST":
        success, msg = register_user(request.form['username'], request.form['password'])
        flash(msg)
        if success:
            return redirect(url_for("login"))

    return render_template("register.html")


# 🔐 LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user' in session:
        return redirect(url_for('index'))

    if request.method == "POST":
        success, msg = login_user(request.form['username'], request.form['password'])
        if success:
            session['user'] = request.form['username']
            return redirect(url_for('index'))

        flash(msg, "danger")

    return render_template("login.html")


# 🚪 LOGOUT
@app.route("/logout")
def logout():
    session.pop('user', None)
    flash("Logged out successfully.")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)