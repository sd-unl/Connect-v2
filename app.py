# --- ADD THIS IMPORT AT THE TOP ---
import requests 

# --- REPLACE THE '/api/authorize' ROUTE WITH THIS ---
@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json or {}
    token = data.get('token')      # <--- We now look for a TOKEN, not just an email
    provided_key = data.get('key')
    
    email = None

    # 1. VERIFY TOKEN WITH GOOGLE
    if token:
        try:
            # Ask Google: "Who owns this token?"
            google_res = requests.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={token}")
            
            if google_res.status_code == 200:
                google_data = google_res.json()
                email = google_data.get('email')
            else:
                return jsonify({"authorized": False, "error": "Invalid Google Token"}), 401
        except Exception as e:
            return jsonify({"authorized": False, "error": f"Token verification failed: {str(e)}"}), 500
    
    # Fallback: If no token provided (or legacy client), check if 'email' was sent manually (Optional: You can remove this to enforce Tokens)
    if not email:
        email = data.get('email')

    if not email:
        return jsonify({"authorized": False, "error": "Authentication failed. No email identified."}), 400

    # 2. PROCEED WITH EXISTING LOGIC (Database Checks)
    with engine.connect() as conn:
        # Check active session
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                return jsonify({"authorized": True, "message": f"Welcome back, {email}"})
            
            conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
            conn.commit()

        # Check License Key
        if not provided_key:
            return jsonify({"authorized": False, "error": "License Key required"}), 401

        row = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
            {"k": provided_key}
        ).fetchone()

        if not row:
            return jsonify({"authorized": False, "error": "Invalid Key"}), 403
        
        status, duration = row
        if status == 'used':
            return jsonify({"authorized": False, "error": "Key already used"}), 403

        # Activate
        new_expiry = datetime.now() + timedelta(hours=duration)
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
        conn.execute(text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), {"e": email, "t": new_expiry})
        conn.commit()

        return jsonify({"authorized": True, "message": "Key Activated Successfully"})
