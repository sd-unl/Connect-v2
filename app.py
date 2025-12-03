import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

# Ensure you set the Environment Variable 'DATABASE_URL' in Render
DB_URL = os.environ.get("DATABASE_URL")
if not DB_URL:
    raise ValueError("DATABASE_URL is not set!")

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
    return "License Server is Running."

# --- ADMIN: Create Key ---
@app.route('/admin/create', methods=['POST'])
def create_key():
    # In a real app, add a password check here!
    key = secrets.token_hex(6) 
    with engine.connect() as conn:
        conn.execute(text("INSERT INTO licenses (key_code) VALUES (:k)"), {"k": key})
        conn.commit()
    return jsonify({"key": key, "status": "created"})

# --- CLIENT: Check/Login ---
@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json
    email = data.get('email')
    provided_key = data.get('key')

    if not email:
        return jsonify({"authorized": False, "error": "Email required"}), 400

    with engine.connect() as conn:
        # 1. Check existing session
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            if datetime.now() < expires_at:
                return jsonify({
                    "authorized": True, 
                    "message": "Session Valid."
                })
            else:
                # Expired
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

        # 2. If we are here, we need a valid Key
        if not provided_key:
            return jsonify({"authorized": False, "error": "Session expired or invalid. Key required."}), 401

        # 3. Validate Key
        key_record = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
            {"k": provided_key}
        ).fetchone()

        if not key_record:
             return jsonify({"authorized": False, "error": "Invalid Key"}), 403
        
        status, duration = key_record

        if status == 'used':
            return jsonify({"authorized": False, "error": "Key already used"}), 403

        # 4. Activate
        new_expiry = datetime.now() + timedelta(hours=duration)
        
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        
        # Insert or Update Session
        conn.execute(text("""
            INSERT INTO active_sessions (user_email, expires_at) 
            VALUES (:e, :t) 
            ON CONFLICT (user_email) DO UPDATE SET expires_at = :t
        """), {"e": email, "t": new_expiry})
        conn.commit()

        return jsonify({"authorized": True, "message": "Key Activated."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
