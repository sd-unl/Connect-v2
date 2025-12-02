import os
import re
import secrets
import threading
import time
import logging
from datetime import datetime, timedelta
from functools import wraps

import requests as http_requests
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

# ============================================================
# CONFIGURATION
# ============================================================

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Database Setup
DB_URL = os.environ.get("DATABASE_URL")
if not DB_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

# Fix for Render's postgres:// URL (SQLAlchemy requires postgresql://)
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DB_URL, pool_pre_ping=True, pool_recycle=300)

# Security Configuration
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")  # REQUIRED - Set in Render env vars
if not ADMIN_TOKEN:
    ADMIN_TOKEN = secrets.token_hex(24)
    app.logger.warning(f"⚠️  No ADMIN_TOKEN set! Generated temporary token: {ADMIN_TOKEN}")

SELF_URL = os.environ.get("RENDER_EXTERNAL_URL", "")
ENABLE_KEEP_ALIVE = os.environ.get("ENABLE_KEEP_ALIVE", "true").lower() == "true"
ENABLE_EMAIL_WHITELIST = os.environ.get("ENABLE_EMAIL_WHITELIST", "false").lower() == "true"

# Rate Limiting (In-memory - use Redis for production with multiple workers)
rate_limit_store = {}
RATE_LIMIT_MAX_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60

# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    """Initialize all required database tables"""
    with engine.connect() as conn:
        # Table 1: One-Time License Keys
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL,
                key_code TEXT PRIMARY KEY,
                status TEXT DEFAULT 'unused' CHECK (status IN ('unused', 'used')),
                duration_hours INT DEFAULT 24 CHECK (duration_hours > 0),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_by_email TEXT,
                used_at TIMESTAMP
            );
        """))
        
        # Table 2: Active User Sessions
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                user_email TEXT PRIMARY KEY,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                key_used TEXT
            );
        """))
        
        # Table 3: Email Whitelist (Optional)
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS allowed_emails (
                email TEXT PRIMARY KEY,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                added_by TEXT DEFAULT 'admin'
            );
        """))
        
        # Table 4: Audit Log
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                event_type TEXT NOT NULL,
                email TEXT,
                ip_address TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        
        # Create indexes for performance
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_sessions_expires 
            ON active_sessions(expires_at);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_audit_created 
            ON audit_log(created_at);
        """))
        
        conn.commit()
        app.logger.info("✅ Database initialized successfully")

# Initialize on startup
try:
    init_db()
except Exception as e:
    app.logger.error(f"❌ Database initialization failed: {e}")
    raise

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def validate_email_format(email: str) -> bool:
    """Validate email format using regex"""
    if not email or not isinstance(email, str):
        return False
    if len(email) > 254:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email.strip()))

def normalize_email(email: str) -> str:
    """Normalize email to lowercase and strip whitespace"""
    return email.strip().lower() if email else ""

def get_client_ip() -> str:
    """Get the real client IP, considering proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP').strip()
    return request.remote_addr or "unknown"

def log_audit_event(event_type: str, email: str = None, details: str = None):
    """Log security events to the database"""
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO audit_log (event_type, email, ip_address, details)
                VALUES (:event, :email, :ip, :details)
            """), {
                "event": event_type,
                "email": email,
                "ip": get_client_ip(),
                "details": details
            })
            conn.commit()
    except SQLAlchemyError as e:
        app.logger.error(f"Failed to log audit event: {e}")

def check_rate_limit(identifier: str) -> bool:
    """
    Simple in-memory rate limiting.
    Returns True if request is allowed, False if rate limited.
    """
    current_time = time.time()
    
    # Clean old entries periodically
    if len(rate_limit_store) > 10000:
        cutoff = current_time - RATE_LIMIT_WINDOW_SECONDS
        keys_to_delete = [k for k, v in rate_limit_store.items() if v['start'] < cutoff]
        for k in keys_to_delete:
            del rate_limit_store[k]
    
    if identifier not in rate_limit_store:
        rate_limit_store[identifier] = {'count': 1, 'start': current_time}
        return True
    
    entry = rate_limit_store[identifier]
    
    # Reset window if expired
    if current_time - entry['start'] > RATE_LIMIT_WINDOW_SECONDS:
        rate_limit_store[identifier] = {'count': 1, 'start': current_time}
        return True
    
    # Check limit
    if entry['count'] >= RATE_LIMIT_MAX_REQUESTS:
        return False
    
    entry['count'] += 1
    return True

def is_email_whitelisted(email: str) -> bool:
    """Check if email is in the whitelist (if whitelist is enabled)"""
    if not ENABLE_EMAIL_WHITELIST:
        return True  # All emails allowed if whitelist disabled
    
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT 1 FROM allowed_emails WHERE email = :e"),
            {"e": email}
        ).fetchone()
        return result is not None

def generate_secure_key() -> str:
    """Generate a cryptographically secure key"""
    # 24 bytes = 48 hex characters = 192 bits of entropy
    return secrets.token_hex(24)

def cleanup_expired_sessions():
    """Remove expired sessions from database"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                DELETE FROM active_sessions 
                WHERE expires_at < :now
            """), {"now": datetime.now()})
            if result.rowcount > 0:
                app.logger.info(f"🧹 Cleaned up {result.rowcount} expired sessions")
            conn.commit()
    except SQLAlchemyError as e:
        app.logger.error(f"Session cleanup failed: {e}")

# ============================================================
# ADMIN AUTHENTICATION DECORATOR
# ============================================================

def require_admin(f):
    """Decorator to protect admin endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check multiple sources for token
        token = (
            request.headers.get('X-Admin-Token') or 
            request.args.get('token') or 
            request.form.get('token')
        )
        
        if not token:
            log_audit_event("ADMIN_NO_TOKEN", details="Missing admin token")
            return jsonify({"error": "Authentication required"}), 401
        
        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(token, ADMIN_TOKEN):
            log_audit_event("ADMIN_INVALID_TOKEN", details="Invalid admin token attempt")
            return jsonify({"error": "Invalid credentials"}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# KEEP-ALIVE MECHANISM
# ============================================================

def keep_alive_worker():
    """Background thread to prevent Render free tier from sleeping"""
    while True:
        time.sleep(780)  # 13 minutes (Render sleeps after 15 min inactivity)
        try:
            if SELF_URL:
                response = http_requests.get(
                    f"{SELF_URL}/health",
                    timeout=30,
                    headers={'User-Agent': 'KeepAlive/1.0'}
                )
                if response.status_code == 200:
                    app.logger.debug("💓 Keep-alive ping successful")
                else:
                    app.logger.warning(f"Keep-alive returned status {response.status_code}")
        except Exception as e:
            app.logger.warning(f"Keep-alive ping failed: {e}")
        
        # Also cleanup expired sessions periodically
        cleanup_expired_sessions()

if ENABLE_KEEP_ALIVE and SELF_URL:
    keep_alive_thread = threading.Thread(target=keep_alive_worker, daemon=True)
    keep_alive_thread.start()
    app.logger.info("✅ Keep-alive worker started")

# ============================================================
# ROUTES: HEALTH CHECK
# ============================================================

@app.route('/')
def home():
    """Simple home page"""
    return jsonify({
        "service": "License Server",
        "status": "running",
        "version": "2.0"
    })

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring services"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e)
        }), 500

# ============================================================
# ROUTES: ADMIN PANEL (PROTECTED)
# ============================================================

@app.route('/admin')
@require_admin
def admin_panel():
    """Admin panel for key generation"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body { font-family: -apple-system, sans-serif; text-align: center; margin: 50px; background: #1a1a2e; color: #eee; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            h1 { color: #00d4ff; }
            button { padding: 15px 30px; font-size: 16px; cursor: pointer; background: #00d4ff; color: #1a1a2e; border: none; border-radius: 8px; margin: 10px; font-weight: bold; }
            button:hover { background: #00a8cc; }
            .result { margin-top: 20px; padding: 20px; background: #16213e; border-radius: 8px; word-break: break-all; }
            .key { font-size: 24px; color: #00ff88; font-family: monospace; }
            .error { color: #ff6b6b; }
            .stats { margin-top: 30px; text-align: left; background: #16213e; padding: 20px; border-radius: 8px; }
            input { padding: 10px; font-size: 14px; border: none; border-radius: 5px; margin: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 License Admin Panel</h1>
            
            <div>
                <h3>Generate Key</h3>
                <input type="number" id="hours" placeholder="Hours (default: 24)" value="24" min="1" max="8760">
                <button onclick="genKey()">🔑 Generate Key</button>
            </div>
            
            <div id="result" class="result" style="display:none;"></div>
            
            <div>
                <h3>Manage Emails</h3>
                <input type="email" id="email" placeholder="user@example.com">
                <button onclick="addEmail()">➕ Add to Whitelist</button>
                <button onclick="removeEmail()">➖ Remove</button>
            </div>
            
            <div>
                <h3>Tools</h3>
                <button onclick="viewStats()">📊 View Stats</button>
                <button onclick="cleanupSessions()">🧹 Cleanup Expired</button>
            </div>
            
            <div id="stats" class="stats" style="display:none;"></div>
        </div>
        
        <script>
            const token = new URLSearchParams(window.location.search).get('token');
            
            async function apiCall(endpoint, method = 'POST', body = null) {
                const options = {
                    method,
                    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': token }
                };
                if (body) options.body = JSON.stringify(body);
                const r = await fetch(endpoint, options);
                return await r.json();
            }
            
            async function genKey() {
                const hours = parseInt(document.getElementById('hours').value) || 24;
                const d = await apiCall('/admin/create', 'POST', { duration_hours: hours });
                const res = document.getElementById('result');
                res.style.display = 'block';
                if (d.key) {
                    res.innerHTML = '<div class="key">' + d.key + '</div><br><small>Duration: ' + hours + ' hours</small>';
                } else {
                    res.innerHTML = '<div class="error">Error: ' + (d.error || 'Unknown') + '</div>';
                }
            }
            
            async function addEmail() {
                const email = document.getElementById('email').value;
                if (!email) return alert('Enter an email');
                const d = await apiCall('/admin/whitelist/add', 'POST', { email });
                alert(d.message || d.error);
            }
            
            async function removeEmail() {
                const email = document.getElementById('email').value;
                if (!email) return alert('Enter an email');
                const d = await apiCall('/admin/whitelist/remove', 'POST', { email });
                alert(d.message || d.error);
            }
            
            async function viewStats() {
                const d = await apiCall('/admin/stats', 'GET');
                const stats = document.getElementById('stats');
                stats.style.display = 'block';
                stats.innerHTML = '<pre>' + JSON.stringify(d, null, 2) + '</pre>';
            }
            
            async function cleanupSessions() {
                const d = await apiCall('/admin/cleanup', 'POST');
                alert(d.message || d.error);
            }
        </script>
    </body>
    </html>
    """

@app.route('/admin/create', methods=['POST'])
@require_admin
def create_key():
    """Generate a new license key"""
    data = request.json or {}
    duration = data.get('duration_hours', 24)
    
    # Validate duration
    try:
        duration = int(duration)
        if not 1 <= duration <= 8760:  # 1 hour to 1 year
            return jsonify({"error": "Duration must be between 1 and 8760 hours"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid duration"}), 400
    
    key = generate_secure_key()
    
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO licenses (key_code, duration_hours)
                VALUES (:key, :duration)
            """), {"key": key, "duration": duration})
            conn.commit()
        
        log_audit_event("KEY_CREATED", details=f"Duration: {duration}h")
        return jsonify({"key": key, "duration_hours": duration})
    
    except SQLAlchemyError as e:
        app.logger.error(f"Failed to create key: {e}")
        return jsonify({"error": "Database error"}), 500

@app.route('/admin/whitelist/add', methods=['POST'])
@require_admin
def add_to_whitelist():
    """Add email to whitelist"""
    data = request.json or {}
    email = normalize_email(data.get('email', ''))
    
    if not validate_email_format(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO allowed_emails (email)
                VALUES (:email)
                ON CONFLICT (email) DO NOTHING
            """), {"email": email})
            conn.commit()
        
        log_audit_event("EMAIL_WHITELISTED", email=email)
        return jsonify({"message": f"Email {email} added to whitelist"})
    
    except SQLAlchemyError as e:
        return jsonify({"error": "Database error"}), 500

@app.route('/admin/whitelist/remove', methods=['POST'])
@require_admin
def remove_from_whitelist():
    """Remove email from whitelist"""
    data = request.json or {}
    email = normalize_email(data.get('email', ''))
    
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                DELETE FROM allowed_emails WHERE email = :email
            """), {"email": email})
            conn.commit()
        
        if result.rowcount > 0:
            log_audit_event("EMAIL_REMOVED_WHITELIST", email=email)
            return jsonify({"message": f"Email {email} removed from whitelist"})
        else:
            return jsonify({"error": "Email not found in whitelist"}), 404
    
    except SQLAlchemyError as e:
        return jsonify({"error": "Database error"}), 500

@app.route('/admin/stats', methods=['GET'])
@require_admin
def get_stats():
    """Get system statistics"""
    try:
        with engine.connect() as conn:
            stats = {
                "unused_keys": conn.execute(text(
                    "SELECT COUNT(*) FROM licenses WHERE status = 'unused'"
                )).scalar(),
                "used_keys": conn.execute(text(
                    "SELECT COUNT(*) FROM licenses WHERE status = 'used'"
                )).scalar(),
                "active_sessions": conn.execute(text(
                    "SELECT COUNT(*) FROM active_sessions WHERE expires_at > :now"
                ), {"now": datetime.now()}).scalar(),
                "expired_sessions": conn.execute(text(
                    "SELECT COUNT(*) FROM active_sessions WHERE expires_at <= :now"
                ), {"now": datetime.now()}).scalar(),
                "whitelisted_emails": conn.execute(text(
                    "SELECT COUNT(*) FROM allowed_emails"
                )).scalar(),
                "total_audit_events": conn.execute(text(
                    "SELECT COUNT(*) FROM audit_log"
                )).scalar()
            }
        return jsonify(stats)
    except SQLAlchemyError as e:
        return jsonify({"error": "Database error"}), 500

@app.route('/admin/cleanup', methods=['POST'])
@require_admin
def admin_cleanup():
    """Manually trigger cleanup of expired sessions"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                DELETE FROM active_sessions WHERE expires_at < :now
            """), {"now": datetime.now()})
            deleted = result.rowcount
            conn.commit()
        
        log_audit_event("MANUAL_CLEANUP", details=f"Removed {deleted} expired sessions")
        return jsonify({"message": f"Cleaned up {deleted} expired sessions"})
    except SQLAlchemyError as e:
        return jsonify({"error": "Database error"}), 500

# ============================================================
# ROUTES: CLIENT AUTHORIZATION
# ============================================================

@app.route('/api/authorize', methods=['POST'])
def authorize():
    """Main authorization endpoint for clients"""
    
    # Rate limiting by IP
    client_ip = get_client_ip()
    if not check_rate_limit(client_ip):
        log_audit_event("RATE_LIMITED", details=f"IP: {client_ip}")
        return jsonify({
            "authorized": False,
            "error": "Too many requests. Please wait a minute."
        }), 429
    
    # Parse request
    data = request.json
    if not data:
        return jsonify({"authorized": False, "error": "Invalid request format"}), 400
    
    email = normalize_email(data.get('email', ''))
    provided_key = (data.get('key') or '').strip()
    
    # Validate email format
    if not email:
        return jsonify({"authorized": False, "error": "Email is required"}), 400
    
    if not validate_email_format(email):
        log_audit_event("INVALID_EMAIL_FORMAT", email=email)
        return jsonify({"authorized": False, "error": "Invalid email format"}), 400
    
    # Check whitelist if enabled
    if ENABLE_EMAIL_WHITELIST and not is_email_whitelisted(email):
        log_audit_event("EMAIL_NOT_WHITELISTED", email=email)
        return jsonify({
            "authorized": False,
            "error": "Email not authorized. Contact administrator."
        }), 403
    
    try:
        with engine.connect() as conn:
            # ============================================
            # STEP 1: Check for existing valid session
            # ============================================
            session = conn.execute(
                text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
                {"e": email}
            ).fetchone()
            
            if session:
                expires_at = session[0]
                if datetime.now() < expires_at:
                    # Update last activity timestamp
                    conn.execute(text("""
                        UPDATE active_sessions 
                        SET last_activity = :now 
                        WHERE user_email = :e
                    """), {"e": email, "now": datetime.now()})
                    conn.commit()
                    
                    time_remaining = expires_at - datetime.now()
                    hours_left = int(time_remaining.total_seconds() // 3600)
                    
                    log_audit_event("SESSION_RESUMED", email=email)
                    return jsonify({
                        "authorized": True,
                        "message": f"Session active. {hours_left}h remaining.",
                        "expires_at": expires_at.isoformat()
                    })
                else:
                    # Session expired - remove it
                    conn.execute(text(
                        "DELETE FROM active_sessions WHERE user_email = :e"
                    ), {"e": email})
                    conn.commit()
                    log_audit_event("SESSION_EXPIRED", email=email)
            
            # ============================================
            # STEP 2: No valid session - require key
            # ============================================
            if not provided_key:
                return jsonify({
                    "authorized": False,
                    "error": "Access key required for new session"
                }), 401
            
            # Validate key length (security measure)
            if len(provided_key) != 48:  # Our keys are 48 chars
                log_audit_event("INVALID_KEY_FORMAT", email=email)
                return jsonify({
                    "authorized": False,
                    "error": "Invalid key format"
                }), 403
            
            # ============================================
            # STEP 3: Validate and consume key (atomic)
            # ============================================
            # Use SELECT FOR UPDATE to prevent race conditions
            key_record = conn.execute(text("""
                SELECT status, duration_hours 
                FROM licenses 
                WHERE key_code = :k
                FOR UPDATE
            """), {"k": provided_key}).fetchone()
            
            if not key_record:
                log_audit_event("KEY_NOT_FOUND", email=email)
                return jsonify({
                    "authorized": False,
                    "error": "Invalid access key"
                }), 403
            
            status, duration = key_record
            
            if status == 'used':
                log_audit_event("KEY_ALREADY_USED", email=email)
                return jsonify({
                    "authorized": False,
                    "error": "This key has already been used"
                }), 403
            
            # ============================================
            # STEP 4: Activate key and create session
            # ============================================
            new_expiry = datetime.now() + timedelta(hours=duration)
            
            # Mark key as used
            conn.execute(text("""
                UPDATE licenses 
                SET status = 'used', used_by_email = :e, used_at = :now 
                WHERE key_code = :k AND status = 'unused'
            """), {"k": provided_key, "e": email, "now": datetime.now()})
            
            # Create or update session
            conn.execute(text("""
                INSERT INTO active_sessions (user_email, expires_at, last_activity, key_used)
                VALUES (:e, :t, :now, :k)
                ON CONFLICT (user_email) DO UPDATE 
                SET expires_at = :t, last_activity = :now, key_used = :k
            """), {"e": email, "t": new_expiry, "now": datetime.now(), "k": provided_key})
            
            conn.commit()
            
            log_audit_event("KEY_ACTIVATED", email=email, details=f"Duration: {duration}h")
            return jsonify({
                "authorized": True,
                "message": f"Access granted for {duration} hours!",
                "expires_at": new_expiry.isoformat()
            })
    
    except SQLAlchemyError as e:
        app.logger.error(f"Database error in authorize: {e}")
        return jsonify({
            "authorized": False,
            "error": "Service temporarily unavailable"
        }), 500

# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"Internal error: {e}")
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {e}")
    return jsonify({"error": "An unexpected error occurred"}), 500

# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
