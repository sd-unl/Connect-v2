import os
import secrets
import urllib.parse
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

# --- CONFIGURATION ---

# 1. Get the raw URL
DB_URL = os.environ.get("DATABASE_URL")

# 🚨 EMERGENCY OVERRIDE:
# If Render fails to read the env var, paste your DIRECT connection string here.
# NOTE: Use the "Direct Connection" string from Supabase (Port 5432), NOT the Pooler.
if not DB_URL:
    # Example: "postgresql://postgres.user:password@aws-0-eu-central-1.supabase.com:5432/postgres"
    DB_URL = "PASTE_YOUR_URL_HERE_IF_NEEDED"

# 2. Fix the URL Connection String
if DB_URL and "PASTE_YOUR" not in DB_URL:
    try:
        # A. Force PostgreSQL driver
        if DB_URL.startswith("postgres://"):
            DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

        # B. URL Encode the Password (The #1 cause of your error)
        # We parse the URL, encode the password, and rebuild it.
        # This fixes passwords with @, #, /, : in them.
        if "@" in DB_URL:
            prefix = "postgresql://"
            # Remove prefix
            clean_url = DB_URL.replace(prefix, "")
            
            # Split into credentials and host
            if "@" in clean_url:
                creds, host = clean_url.rsplit("@", 1)
                
                if ":" in creds:
                    user, password = creds.split(":", 1)
                    # Encode the password safely
                    safe_password = urllib.parse.quote_plus(password)
                    DB_URL = f"{prefix}{user}:{safe_password}@{host}"

        # C. Force SSL Mode (Required for Supabase)
        if "?sslmode=" not in DB_URL:
            if "?" in DB_URL:
                DB_URL += "&sslmode=require"
            else:
                DB_URL += "?sslmode=require"
        
        print(f"✅ Connection String Configured (Password Hidden)")

        # Create Engine
        engine = create_engine(DB_URL, pool_pre_ping=True)
        
    except Exception as e:
        print(f"❌ Configuration Error: {e}")
        engine = create_engine("sqlite:///temp.db")
else:
    print("⚠️ No DB_URL found. Using local SQLite.")
    engine = create_engine("sqlite:///temp.db")


# --- DATABASE INIT ---
def init_db():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1")) # Test connection
            print("✅ Database Connected Successfully!")
            
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS licenses (
                    key_code TEXT PRIMARY KEY,
                    status TEXT DEFAULT 'unused',
                    duration_hours INT DEFAULT 24
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS active_sessions (
                    user_email TEXT PRIMARY KEY,
                    expires_at TIMESTAMP
                );
            """))
            conn.commit()
    except Exception as e:
        print(f"❌ DATABASE ERROR: {e}")
        print("💡 HINT: Check your password for typos.")
        print("💡 HINT: In Supabase, use 'Connection String' -> 'Direct Connection' (Port 5432).")

init_db()

# --- ROUTES ---
@app.route('/')
def home():
    return "License Server Online"

@app.route('/admin')
def admin_ui():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Admin Panel</title></head>
    <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1>🔑 Key Generator</h1>
        <button onclick="generate()" style="padding: 10px 20px;">Generate Key</button>
        <p id="result" style="font-family: monospace; font-size: 20px; font-weight: bold; margin-top: 20px;"></p>
        <script>
            async function generate() {
                try {
                    const res = await fetch('/admin/create', { method: 'POST' });
                    const data = await res.json();
                    document.getElementById('result').innerText = data.key || data.error;
                } catch (e) {
                    document.getElementById('result').innerText = "Error connecting to server";
                }
            }
        </script>
    </body>
    </html>
    """

@app.route('/admin/create', methods=['POST'])
def create_key_api():
    key = secrets.token_hex(8)
    try:
        with engine.connect() as conn:
            conn.execute(text("INSERT INTO licenses (key_code) VALUES (:k)"), {"k": key})
            conn.commit()
        return jsonify({"key": key})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json or {}
    email = data.get('email')
    provided_key = data.get('key')

    if not email:
        return jsonify({"authorized": False, "error": "Email required"}), 400

    try:
        with engine.connect() as conn:
            # 1. Check Session
            session = conn.execute(
                text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
                {"e": email}
            ).fetchone()

            if session:
                expires_at = session[0]
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                
                if datetime.now() < expires_at:
                    return jsonify({"authorized": True, "message": "Session Valid"})
                else:
                    conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                    conn.commit()

            # 2. Check Key
            if not provided_key:
                return jsonify({"authorized": False, "error": "Key required"}), 401

            row = conn.execute(
                text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
                {"k": provided_key}
            ).fetchone()

            if not row:
                return jsonify({"authorized": False, "error": "Invalid Key"}), 403
            
            status, duration = row
            if status == 'used':
                return jsonify({"authorized": False, "error": "Key Used"}), 403

            # 3. Activate
            new_expiry = datetime.now() + timedelta(hours=duration)
            conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
            
            # Upsert
            conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
            conn.execute(text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), {"e": email, "t": new_expiry})
            conn.commit()

            return jsonify({"authorized": True, "message": "Access Granted"})

    except Exception as e:
        return jsonify({"authorized": False, "error": "DB Connection Failed"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
