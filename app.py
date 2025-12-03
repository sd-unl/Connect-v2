import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

# Database Connection
DB_URL = os.environ.get("DATABASE_URL")
if not DB_URL:
    print("WARNING: DATABASE_URL is not set. Using temporary local DB.")
    engine = create_engine("sqlite:///temp.db") # Fallback for local testing
else:
    engine = create_engine(DB_URL)

def init_db():
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

init_db()

@app.route('/')
def home():
    return "License Server is Online."

# --- NEW: VISUAL ADMIN PANEL ---
@app.route('/admin')
def admin_ui():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body { font-family: sans-serif; text-align: center; padding: 50px; background: #f4f4f4; }
            .box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); display: inline-block; }
            button { background: #007bff; color: white; border: none; padding: 15px 30px; font-size: 18px; border-radius: 5px; cursor: pointer; }
            button:hover { background: #0056b3; }
            #result { margin-top: 20px; font-size: 24px; font-family: monospace; color: #28a745; font-weight: bold; background: #e8f5e9; padding: 10px; border-radius: 5px; display: none;}
        </style>
    </head>
    <body>
        <div class="box">
            <h1>🔑 Key Generator</h1>
            <p>Generate a one-time use key for your clients.</p>
            <button onclick="generate()">Generate New Key</button>
            <div id="result"></div>
        </div>

        <script>
            async function generate() {
                const res = await fetch('/admin/create', { method: 'POST' });
                const data = await res.json();
                const display = document.getElementById('result');
                display.style.display = 'block';
                display.innerText = data.key;
            }
        </script>
    </body>
    </html>
    """

# --- API: Create Key (Backend) ---
@app.route('/admin/create', methods=['POST'])
def create_key_api():
    key = secrets.token_hex(8) # Generates 16 character key
    with engine.connect() as conn:
        conn.execute(text("INSERT INTO licenses (key_code) VALUES (:k)"), {"k": key})
        conn.commit()
    return jsonify({"key": key, "status": "created"})

# --- API: Authorize Client ---
@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json
    email = data.get('email')
    provided_key = data.get('key')

    if not email:
        return jsonify({"authorized": False, "error": "Email required"}), 400

    with engine.connect() as conn:
        # 1. Check active session
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            # Convert string to datetime if SQLite is used (SQLite stores dates as strings)
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
                
            if datetime.now() < expires_at:
                return jsonify({"authorized": True, "message": "Session Valid."})
            else:
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

        # 2. Check Key
        if not provided_key:
            return jsonify({"authorized": False, "error": "Session expired. Key required."}), 401

        key_record = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
            {"k": provided_key}
        ).fetchone()

        if not key_record:
             return jsonify({"authorized": False, "error": "Invalid Key"}), 403
        
        status, duration = key_record

        if status == 'used':
            return jsonify({"authorized": False, "error": "Key already used"}), 403

        # 3. Activate
        new_expiry = datetime.now() + timedelta(hours=duration)
        
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        
        # SQLite vs Postgres syntax diff handling is minor here, but standard SQL usually works:
        try:
            # PostgreSQL Syntax
            conn.execute(text("""
                INSERT INTO active_sessions (user_email, expires_at) 
                VALUES (:e, :t) 
                ON CONFLICT (user_email) DO UPDATE SET expires_at = :t
            """), {"e": email, "t": new_expiry})
        except:
            # Fallback for SQLite (if testing locally)
            conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
            conn.execute(text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), {"e": email, "t": new_expiry})
            
        conn.commit()

        return jsonify({"authorized": True, "message": "Key Activated."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
