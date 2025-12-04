import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

# --- FIX 1: HANDLE SUPABASE URL FORMAT ---
# SQLAlchemy requires 'postgresql://', but Supabase/Render often gives 'postgres://'
DB_URL = os.environ.get("DATABASE_URL")

if not DB_URL:
    # Fail loud if no DB is configured
    raise ValueError("❌ DATABASE_URL is missing! Set it in Render Environment.")

if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

# Use connection pooling (good for Supabase)
engine = create_engine(DB_URL, pool_size=10, max_overflow=20)

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

# --- ADMIN PANEL (Simplified for brevity) ---
@app.route('/admin')
def admin_ui():
    return """
    <button onclick="fetch('/admin/create',{method:'POST'}).then(r=>r.json()).then(d=>alert(d.key))">
    Generate Key</button>
    """

@app.route('/admin/create', methods=['POST'])
def create_key():
    key = secrets.token_hex(8)
    with engine.connect() as conn:
        conn.execute(text("INSERT INTO licenses (key_code) VALUES (:k)"), {"k": key})
        conn.commit()
    return jsonify({"key": key})

# --- API: AUTHORIZE ---
@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json
    email = data.get('email')
    provided_key = data.get('key')

    if not email:
        return jsonify({"authorized": False, "error": "No Email Detected"}), 400

    print(f"🔹 Processing Auth Request for: {email}") # Log for debugging

    with engine.connect() as conn:
        # 1. Check Session
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            # Handle potential string/datetime mismatch from DB driver
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
            return jsonify({"authorized": False, "error": "Session Expired. Key Required."}), 401

        # 3. Validate Key
        key_record = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
            {"k": provided_key}
        ).fetchone()

        if not key_record:
            return jsonify({"authorized": False, "error": "Invalid Key"}), 403

        status, duration = key_record
        if status == 'used':
            return jsonify({"authorized": False, "error": "Key Already Used"}), 403

        # 4. Success - Save to DB
        new_expiry = datetime.now() + timedelta(hours=duration)
        
        # Mark Key Used
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        
        # Create Session (Upsert)
        conn.execute(text("""
            INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)
            ON CONFLICT (user_email) DO UPDATE SET expires_at = :t
        """), {"e": email, "t": new_expiry})
        
        conn.commit() # <--- CRITICAL: SAVES TO SUPABASE
        print(f"✅ Saved session for {email}")

        return jsonify({"authorized": True, "message": "Key Activated"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
