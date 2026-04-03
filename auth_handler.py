import json
import os
from werkzeug.security import generate_password_hash, check_password_hash

USER_FILE = "data/users.json"

def ensure_data_folder():
    if not os.path.exists("data"): os.makedirs("data")
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "w") as f: json.dump({}, f)

def register_user(username, password):
    ensure_data_folder()
    with open(USER_FILE, "r") as f: users = json.load(f)
    if username in users: return False, "❌ Username exists!"
    users[username] = generate_password_hash(password)
    with open(USER_FILE, "w") as f: json.dump(users, f, indent=4)
    return True, "✅ Success! Please login."

def login_user(username, password):
    ensure_data_folder()
    with open(USER_FILE, "r") as f: users = json.load(f)
    if username in users and check_password_hash(users[username], password):
        return True, "✅ Login Successful"
    return False, "❌ Invalid Credentials"