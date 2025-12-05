import os
import secrets
import sys
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

# --- 1. CONFIGURATION ---
# Try to get URL from Render Environment
DB_URL = os.environ.get("DATABASE_URL")

# ---------------------------------------------------------
# 🚨 EMERGENCY FIX: If Env Variable fails, paste URL below
# ---------------------------------------------------------
if not DB_URL:
    # 👇 PASTE YOUR FULL SUPABASE URL INSIDE THE QUOTES BELOW (Use Port 5432!)
    # Example: "postgresql://postgres.xxx:password@aws-0-eu-central-1.pooler.supabase.com:5432/postgres"
    DB_URL = "Paste_Your_Supabase_URL_Here" 

    # If you left it as the placeholder text, reset to None
    if "Paste_Your_Supabase_URL_Here" in DB_URL:
        DB_URL = None
# ---------------------------------------------------------

# --- 2. DATABASE CONNECTION ---
if not DB_URL:
    print("❌ CRITICAL ERROR: DATABASE_URL is missing!")
    print("   -> Go to Render Dashboard > Environment > Add 'DATABASE_URL'")
    print("   -> Or paste it into the 'EMERGENCY FIX' section in app.py")
    # Fallback to prevent crash, but data will be lost on restart
    engine = create_engine("sqlite:///temp.db")
else:
    # Fix: SQLAlchemy requires 'postgresql://', not 'postgres://'
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    
    print("🔄 Attempting to connect to Database...")
    
    try:
        # Create engine with a ping check to keep connection alive
        engine = create_engine(DB_URL, pool_pre_ping=True)
        
        # Test Connection Immediately
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            print("✅ SUCCESS: Connected to Supabase!")
    except Exception as e:
        print(f"❌ DATABASE CONNECTION FAILED: {e}")
        print("   -> Check your Password")
        print("   -> Ensure you are using Port 5432 (Not 6543)")
        # Fallback
        engine = create_engine("sqlite:///temp.db")

def init_db():
    try:
        with engine.connect() as conn:
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
        print(f"⚠️ Init DB Error: {e}")

init_db()

@app.route('/')
def home():
    return "License Server is Online."

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
                const res = await fetch('/admin/create', { method: 'POST' });
                const data = await res.json();
                document.getElementById('result').innerText = data.key || data.error;
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
            # 1. Check active session
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
                return jsonify({"authorized": False, "error": "Key already used"}), 403

            # 3. Activate
            new_expiry = datetime.now() + timedelta(hours=duration)
            conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
            
            # Upsert Logic
            conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
            conn.execute(text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), {"e": email, "t": new_expiry})
            conn.commit()

            return jsonify({"authorized": True, "message": "Access Granted"})

    except Exception as e:
        print(f"❌ Runtime DB Error: {e}")
        return jsonify({"authorized": False, "error": "Server Database Error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
