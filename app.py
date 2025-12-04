import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

# --- DATABASE CONFIGURATION ---
DB_URL = os.environ.get("DATABASE_URL")

if DB_URL:
    # FIX: SQLAlchemy requires 'postgresql://', but Render/Supabase often gives 'postgres://'
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    
    # Create Engine
    engine = create_engine(DB_URL)
else:
    # Fallback for local testing ONLY
    print("⚠️ WARNING: DATABASE_URL not set. Using temporary local SQLite.")
    engine = create_engine("sqlite:///temp.db")

def init_db():
    with engine.connect() as conn:
        # Create tables
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

init_db()

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
        <button onclick="generate()" style="padding: 10px 20px; font-size: 16px;">Generate Key</button>
        <p id="result" style="font-family: monospace; font-size: 20px; margin-top: 20px; font-weight: bold;"></p>
        <script>
            async function generate() {
                const res = await fetch('/admin/create', { method: 'POST' });
                const data = await res.json();
                document.getElementById('result').innerText = data.key;
            }
        </script>
    </body>
    </html>
    """

@app.route('/admin/create', methods=['POST'])
def create_key_api():
    key = secrets.token_hex(8)
    with engine.connect() as conn:
        conn.execute(text("INSERT INTO licenses (key_code) VALUES (:k)"), {"k": key})
        conn.commit()
    return jsonify({"key": key})

@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json or {}
    email = data.get('email')
    provided_key = data.get('key')

    if not email:
        return jsonify({"authorized": False, "error": "Email missing"}), 400

    with engine.connect() as conn:
        # 1. Check existing session
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            # Handle string dates (SQLite) vs datetime objects (Postgres)
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                return jsonify({"authorized": True, "message": "Session Valid"})
            
            # Expired: clean up
            conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
            conn.commit()

        # 2. If no session, validate Key
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
        
        # Upsert (Handle Postgres vs SQLite syntax safely via delete-insert)
        conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
        conn.execute(text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), {"e": email, "t": new_expiry})
        conn.commit()

        return jsonify({"authorized": True, "message": "Activated"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
