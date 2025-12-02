import os
import secrets
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- CONFIGURATION ---
# Security: Add a simple secret for Admin actions so bots don't generate keys
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change_this_to_something_complex") 
DB_URL = os.environ.get("DATABASE_URL")

engine = create_engine(DB_URL)

def init_db():
    with engine.connect() as conn:
        # 1. Licenses
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS licenses (
                key_code TEXT PRIMARY KEY,
                status TEXT DEFAULT 'unused',
                duration_hours INT DEFAULT 24
            );
        """))
        # 2. Active Sessions
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                user_email TEXT PRIMARY KEY,
                expires_at TIMESTAMP
            );
        """))
        # 3. Whitelist (NEW) - Users allowed to use the tool
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS whitelist (
                email TEXT PRIMARY KEY,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        conn.commit()

init_db()

def get_secret_code():
    """Reads the actual Python code you want to protect."""
    try:
        # Create a file named 'secret_tool.py' in your Render project
        with open('secret_tool.py', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "print('Error: Secret tool file not found on server.')"

# --- ADMIN ROUTES ---

@app.route('/admin')
def admin_panel():
    # Simple HTML interface
    return f"""
    <div style="font-family:sans-serif; max-width:600px; margin:auto; padding:20px;">
        <h1>🛡️ Admin Panel</h1>
        
        <h3>1. Add User to Whitelist</h3>
        <input id="w_email" placeholder="user@gmail.com">
        <input id="adm_pass" type="password" placeholder="Admin Secret">
        <button onclick="addUser()">Add User</button>
        <p id="w_res"></p>

        <hr>

        <h3>2. Generate Key</h3>
        <button onclick="genKey()">Generate 24h Key</button>
        <div id="k_res" style="font-size:20px; font-weight:bold; color:green; margin-top:10px;"></div>

        <script>
            async function addUser() {{
                let email = document.getElementById('w_email').value;
                let secret = document.getElementById('adm_pass').value;
                let r = await fetch('/admin/whitelist', {{
                    method:'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{email: email, secret: secret}})
                }});
                let d = await r.json();
                document.getElementById('w_res').innerText = d.message || d.error;
            }}

            async function genKey() {{
                let secret = document.getElementById('adm_pass').value;
                let r = await fetch('/admin/create_key', {{
                    method:'POST', 
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{secret: secret}})
                }});
                let d = await r.json();
                document.getElementById('k_res').innerText = d.key || d.error;
            }}
        </script>
    </div>
    """

@app.route('/admin/whitelist', methods=['POST'])
def add_whitelist():
    data = request.json
    if data.get('secret') != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    
    email = data.get('email')
    if not email:
        return jsonify({"error": "No email provided"}), 400

    try:
        with engine.connect() as conn:
            conn.execute(
                text("INSERT INTO whitelist (email) VALUES (:e) ON CONFLICT (email) DO NOTHING"),
                {"e": email}
            )
            conn.commit()
        return jsonify({"message": f"Added {email} to whitelist."})
    except Exception as e:
        logger.error(e)
        return jsonify({"error": "Database error"}), 500

@app.route('/admin/create_key', methods=['POST'])
def create_key():
    data = request.json
    if data.get('secret') != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    key = secrets.token_hex(8)
    with engine.connect() as conn:
        conn.execute(text("INSERT INTO licenses (key_code) VALUES (:k)"), {"k": key})
        conn.commit()
    return jsonify({"key": key})

# --- HEALTH CHECK (Anti-Sleep) ---
@app.route('/health', methods=['GET'])
def health_check():
    # External pingers will hit this URL
    return "Alive", 200

# --- CLIENT AUTHORIZATION ---
@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json
    email = data.get('email')
    provided_key = data.get('key')

    if not email:
        return jsonify({"authorized": False, "error": "No Email Provided"}), 400

    with engine.connect() as conn:
        # CHECK 1: IS EMAIL WHITELISTED?
        # Only allow whitelisted emails to proceed
        is_allowed = conn.execute(
            text("SELECT email FROM whitelist WHERE email = :e"),
            {"e": email}
        ).fetchone()

        if not is_allowed:
            return jsonify({
                "authorized": False, 
                "error": "This email is not authorized to use the tool. Contact Admin."
            }), 403

        # CHECK 2: EXISTING SESSION
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            if datetime.now() < expires_at:
                # Session valid: SEND THE SECRET CODE
                return jsonify({
                    "authorized": True, 
                    "message": "Session valid.",
                    "payload": get_secret_code()
                })
            else:
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

        # CHECK 3: VALIDATE NEW KEY
        if not provided_key:
            return jsonify({"authorized": False, "error": "Session expired or missing. Key required."}), 401

        key_record = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
            {"k": provided_key}
        ).fetchone()

        if not key_record:
             return jsonify({"authorized": False, "error": "Invalid Key"}), 403
        
        status, duration = key_record

        if status == 'used':
            return jsonify({"authorized": False, "error": "Key already used"}), 403

        # ACTIVATE
        new_expiry = datetime.now() + timedelta(hours=duration)
        
        # Transaction ensures atomicity
        try:
            conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
            conn.execute(text("""
                INSERT INTO active_sessions (user_email, expires_at) 
                VALUES (:e, :t) 
                ON CONFLICT (user_email) DO UPDATE SET expires_at = :t
            """), {"e": email, "t": new_expiry})
            conn.commit()
        except Exception as e:
            conn.rollback()
            return jsonify({"authorized": False, "error": "Database Transaction Error"}), 500

        return jsonify({
            "authorized": True, 
            "message": "Key Activated.",
            "payload": get_secret_code() 
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
