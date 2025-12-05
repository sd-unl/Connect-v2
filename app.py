import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

# ============ DATABASE CONNECTION (FIXED) ============
DB_URL = os.environ.get("DATABASE_URL")

if not DB_URL:
    print("WARNING: DATABASE_URL is not set. Using temporary local DB.")
    engine = create_engine("sqlite:///temp.db")
else:
    # FIX 1: Handle postgres:// vs postgresql:// (some platforms use old format)
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    
    # FIX 2: Add SSL mode for Supabase (REQUIRED!)
    if "sslmode" not in DB_URL:
        DB_URL += "?sslmode=require"
    
    print(f"Connecting to database...")  # Debug log
    engine = create_engine(DB_URL)

# ============ DATABASE INITIALIZATION ============
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
        print("✅ Database initialized successfully!")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")

init_db()

@app.route('/')
def home():
    # Add database status check
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return "✅ License Server is Online. Database Connected!"
    except Exception as e:
        return f"⚠️ Server Online, but Database Error: {e}"

# --- VISUAL ADMIN PANEL ---
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

# --- API: Create Key ---
@app.route('/admin/create', methods=['POST'])
def create_key_api():
    key = secrets.token_hex(8)
    try:
        with engine.connect() as conn:
            conn.execute(text("INSERT INTO licenses (key_code) VALUES (:k)"), {"k": key})
            conn.commit()
        return jsonify({"key": key, "status": "created"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- API: Authorize Client ---
@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json
    email = data.get('email')
    provided_key = data.get('key')

    if not email:
        return jsonify({"authorized": False, "error": "Email required"}), 400

    with engine.connect() as conn:
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
                
            if datetime.now() < expires_at:
                return jsonify({"authorized": True, "message": "Session Valid."})
            else:
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

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

        new_expiry = datetime.now() + timedelta(hours=duration)
        
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        
        # PostgreSQL UPSERT
        conn.execute(text("""
            INSERT INTO active_sessions (user_email, expires_at) 
            VALUES (:e, :t) 
            ON CONFLICT (user_email) DO UPDATE SET expires_at = EXCLUDED.expires_at
        """), {"e": email, "t": new_expiry})
            
        conn.commit()

        return jsonify({"authorized": True, "message": "Key Activated."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
