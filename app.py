"""ScamShield MY — Malaysia scam phone number & message risk scanner."""
import re
import sqlite3
import hashlib
import os
import time
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template, make_response, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB upload limit

# === Database ===
DB_PATH = os.path.join(os.path.dirname(__file__), 'scamshield.db')

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT,
        phone_normalized TEXT,
        message TEXT,
        sender TEXT,
        scam_type TEXT DEFAULT 'unknown',
        risk_score INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending', -- pending/approved/rejected/fp (false positive)
        reporter_ip_hash TEXT,
        reporter_email TEXT,
        evidence_urls TEXT, -- JSON list
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_by INTEGER,
        reviewed_at TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scores (
        phone_normalized TEXT PRIMARY KEY,
        current_score INTEGER DEFAULT 0,
        last_reported TIMESTAMP,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_reports INTEGER DEFAULT 0,
        scam_reports INTEGER DEFAULT 0,
        legit_reports INTEGER DEFAULT 0,
        blacklisted BOOLEAN DEFAULT 0,
        whitelisted BOOLEAN DEFAULT 0,
        manual_override BOOLEAN DEFAULT 0,
        override_score INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
        phone_normalized TEXT PRIMARY KEY,
        reason TEXT,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        added_by INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS whitelist (
        phone_normalized TEXT PRIMARY KEY,
        reason TEXT,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        added_by INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS feeds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        url TEXT,
        type TEXT, -- mcmc, bank-negara, pdrm, etc.
        last_refreshed TIMESTAMP,
        status TEXT DEFAULT 'active'
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS domains (
        domain TEXT PRIMARY KEY,
        risk_score INTEGER DEFAULT 0,
        source TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS senders (
        sender TEXT PRIMARY KEY,
        is_known BOOLEAN DEFAULT 0,
        is_scam BOOLEAN DEFAULT 0,
        risk_score INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()

# === Constants ===
MALAYSIA_PREFIX = re.compile(r'^(?:\+?60|0)1[0-9]\d{7,8}$')
DANGER_RANGES = {'011', '013', '014', '015', '017', '018'}
SAFE_RANGES = {'012', '016', '019'}
KNOWN_SCAM_SENDERS = {
    'SPM', 'JPA', 'Suruhanjaya', 'EPF', 'KWAP', 'BNM', 'MCMC',
    'Pos Laju', 'DHL', 'FedEx', 'J&T', 'Lalamove',
    'Maybank', 'CIMB', 'Public Bank', 'Maybank2U', 'Touch \'n Go',
    'Grab', 'Foodpanda', 'Uber', 'AirAsia', 'Malaysia Airlines',
}

def hash_ip(ip):
    """GDPR-safe IP hashing."""
    return hashlib.sha256(ip.encode()).hexdigest()[:32] if ip else None

def normalize_number(phone):
    phone = re.sub(r'[^\d+]', '', phone or '')
    if phone.startswith('+60'):
        phone = '0' + phone[3:]
    elif phone.startswith('60') and len(phone) >= 10 and phone[2] == '1':
        phone = '0' + phone[2:]
    return phone

def extract_area_code(phone_norm):
    """Extract the 3-digit area code (01X)."""
    if phone_norm and phone_norm.startswith('0') and len(phone_norm) >= 4:
        return phone_norm[:3]
    return None

def extract_domains(text):
    """Extract domains/URLs from message text."""
    urls = re.findall(r'https?://[^\s]+', text or '')
    domains = []
    for url in urls:
        m = re.match(r'https?://([^/]+)', url)
        if m:
            domains.append(m.group(1))
    return domains

def extract_sender(message):
    """Try to detect sender from message patterns."""
    if not message:
        return None
    lower = message.lower()
    patterns = [
        r'sender[:\s]*([A-Z][A-Z\s]+)\b',
        r'from:\s*([A-Z]{2,})',
    ]
    for pat in patterns:
        m = re.search(pat, message)
        if m:
            return m.group(1).strip()
    return None

# === Scoring Engine ===
def compute_risk_score(phone_norm, message='', sender='', reporter_ip_hash='', phone_db=None):
    """
    Compute risk score without relying on prefix-only assumptions.
    Returns integer score and list of matched signals.
    """
    signals = []
    score = 0
    area_code = extract_area_code(phone_norm)

    # Base: unknown number, no data
    if not phone_db:
        score += 0
        signals.append("New number (no historical data)")

    # Prefix range (LOW weight only — not decisive)
    if area_code in DANGER_RANGES:
        score += 5
        signals.append(f"Prefix {area_code} is scam-heavy range (low weight)")

    if area_code in SAFE_RANGES:
        score -= 5
        signals.append(f"Prefix {area_code} is verified carrier range")

    # Message-based scoring (high signal)
    if message:
        msg_lower = message.lower()
        # Urgency
        urgency_patterns = [
            r'aktiv', r'deactivate', r'suspended', r'suspended', r'immediate',
            r'urgent', r'within.*?hour', r'24.*?hour', r'last chance',
            r'account.*will.*close', r'verify.*now', r'immediate action'
        ]
        for pat in urgency_patterns:
            if re.search(pat, msg_lower):
                score += 10
                signals.append("Urgent language detected")
                break

        # OTP requests
        otp_patterns = [
            r'otp', r'verification code', r'security code', r'pin',
            r'kod.*?sl', r'makluan', r'token', r'kod akses'
        ]
        for pat in otp_patterns:
            if re.search(pat, msg_lower):
                score += 15
                signals.append("OTP/code request detected")
                break

        # URLs
        urls = re.findall(r'https?://[^\s]+', message)
        if urls:
            score += 5
            signals.append(f"Contains {len(urls)} URL(s)")
            if len(urls) > 2:
                score += 5
                signals.append("Multiple URLs — higher risk")
            for url in urls:
                tld = re.search(r'\.(tk|ml|ga|cf|gq)', url)
                if tld:
                    score += 20
                    signals.append(f"Suspicious TLD in URL")
                if 'bit.ly' in url or 'tinyurl' in url:
                    score += 5
                    signals.append("URL shortener detected")

        # Common scam keywords
        scam_kw = {
            'dolar': 15, 'duit': 5, 'uang': 5, 'invest': 10,
            'harga emas': 15, 'lottery': 15, 'hadiah': 15,
            'menang': 10, 'bonus': 8, 'pelaburan': 10,
            'job': 8, 'kerja': 8, 'commission': 10,
            'payout': 10, 'roi': 8, 'trading': 8,
            'phishing': 30, 'verifikasi': 5, 'sah': 5,
            'simpan': 10, 'bank': 10, 'tabungan': 8,
            'polis': 20, 'police': 20, 'imigresen': 15,
            'pajak': 10, 'cukai': 10, 'samun': 20,
        }
        matched_kw = []
        for kw, pts in scam_kw.items():
            if kw in msg_lower:
                score += pts
                matched_kw.append(kw)
        if matched_kw:
            signals.append(f"Scam keywords: {', '.join(matched_kw[:3])}")

        # Claim impersonation
        claims = ['bank', 'pos laju', 'dhl', 'epf', 'kwsp', 'jpn', 'polis',
                  'imigresen', 'pajak', 'malaysia airline', 'airasia',
                  'government', 'suruhanjaya', 'agensi', 'pdrm']
        matched_claims = []
        for cl in claims:
            if cl in msg_lower:
                matched_claims.append(cl)
                score += 10
        if matched_claims:
            signals.append(f"Claims impersonation: {', '.join(matched_claims[:2])}")

        # Fake sender check
        if sender:
            if sender.lower() not in [s.lower() for s in KNOWN_SCAM_SENDERS]:
                score += 15
                signals.append(f"Unknown/unverified sender ID: {sender}")
    else:
        signals.append("No message submitted — scoring based on number only (low confidence)")

    # Length / validity checks
    if len(phone_norm) < 10 or len(phone_norm) > 11:
        score += 10
        signals.append("Non-standard length")

    # Clamp
    score = max(-50, min(200, score))

    return score, signals

def get_status(score):
    """Convert score to human-readable status."""
    if score >= 75:
        return 'DANGER'
    elif score >= 50:
        return 'HIGH_RISK'
    elif score >= 25:
        return 'SUSPICIOUS'
    elif score <= -20:
        return 'SAFE'
    elif score < 0:
        return 'LIKELY_SAFE'
    else:
        return 'UNKNOWN'

def classify_scam_type(message):
    """Auto-classify scam type from message text."""
    if not message:
        return 'unknown'
    ml = message.lower()
    if any(w in ml for w in ['otp', 'verification code', 'security code', 'makluan', 'token']):
        return 'otp_phishing'
    if any(w in ml for w in ['bank', 'maybank', 'cimb', 'atm', 'account']):
        return 'bank_impersonation'
    if any(w in ml for w in ['pos laju', 'dhl', 'fedex', 'j&t', 'lalamove', 'penghantaran']):
        return 'courier_impersonation'
    if any(w in ml for w in ['polis', 'police', 'imigresen', 'pdrm', 'pajak']):
        return 'authority_impersonation'
    if any(w in ml for w in ['dolar', 'emas', 'invest', 'pelaburan', 'roi', 'payout']):
        return 'investment_fraud'
    if any(w in ml for w in ['job', 'kerja', 'komisen']):
        return 'job_scam'
    if any(w in ml for w in ['hadiah', 'lottery', 'menang', 'bonus']):
        return 'prize_phishing'
    if any(w in ml for w in ['epf', 'kwsp', 'jpn', 'suruhanjaya']):
        return 'govt_impersonation'
    return 'general'

# === Routes ===

@app.route('/')
def index():
    resp = make_response(render_template('index.html'))
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

# --- Core API ---
@app.route('/api/check')
def api_check():
    phone = request.args.get('q', '').strip()
    message = request.args.get('msg', '')
    sender = request.args.get('sender', '')

    if not phone:
        return jsonify({'error': 'Missing query parameter: q'}), 400

    phone_norm = normalize_number(phone)
    conn = get_db()

    # Get stored score if any
    row = conn.execute(
        'SELECT * FROM scores WHERE phone_normalized = ?',
        (phone_norm,)
    ).fetchone()

    # Get blacklist/whitelist status
    bl = conn.execute('SELECT 1 FROM blacklist WHERE phone_normalized = ?', (phone_norm,)).fetchone()
    wl = conn.execute('SELECT 1 FROM whitelist WHERE phone_normalized = ?', (phone_norm,)).fetchone()

    # Compute fresh score with message context
    db_score = row['current_score'] if row else 0
    fresh_score, signals = compute_risk_score(phone_norm, message, sender, None)

    # Combine: use fresh score if higher, respect manual override
    if row and row['manual_override']:
        final_score = row['override_score']
        status = get_status(final_score)
        signals = [f"Manually overridden by moderator"]
    else:
        if row and row['whitelisted']:
            final_score = -30
        elif row and row['blacklisted']:
            final_score = max(fresh_score, 60)
        else:
            final_score = fresh_score
        status = get_status(final_score)

    area_code = extract_area_code(phone_norm)
    result = {
        'input': phone,
        'normalized': phone_norm,
        'area_code': area_code,
        'valid_malaysia': bool(MALAYSIA_PREFIX.match(phone_norm)) if phone_norm else False,
        'risk_score': final_score,
        'confidence': 'HIGH' if message else 'LOW' if not row else 'MEDIUM',
        'status': status,
        'signals': signals,
        'scam_type': classify_scam_type(message) if message else None,
        'total_reports': row['total_reports'] if row else 0,
        'blacklisted': bool(bl),
        'whitelisted': bool(wl),
        'last_reported': row['last_reported'] if row else None,
        'first_seen': row['first_seen'] if row else None,
    }
    conn.close()
    return jsonify(result)

@app.route('/api/report', methods=['POST'])
def api_report():
    phone = request.form.get('phone', '').strip()
    message = request.form.get('message', '')
    sender = request.form.get('sender', '')
    reporter_email = request.form.get('email', '')
    evidence_urls = request.form.get('evidence_urls', '')

    if not phone:
        return jsonify({'error': 'Phone number required'}), 400

    phone_norm = normalize_number(phone)
    ip_hash = hash_ip(request.remote_addr or '0.0.0.0')
    scam_type = classify_scam_type(message)
    score, _ = compute_risk_score(phone_norm, message, sender, ip_hash)
    status = get_status(score)

    conn = get_db()
    conn.execute('''INSERT INTO reports
        (phone, phone_normalized, message, sender, scam_type, risk_score, status,
         reporter_ip_hash, reporter_email, evidence_urls)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)''',
        (phone, phone_norm, message, sender, scam_type, score, ip_hash, reporter_email, evidence_urls))
    conn.commit()
    report_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

    # Update score cache
    conn.execute('''INSERT OR IGNORE INTO scores (phone_normalized) VALUES (?)''', (phone_norm,))
    conn.execute('''UPDATE scores SET
        current_score = CASE WHEN current_score > ? THEN current_score ELSE ? END,
        last_reported = datetime('now'),
        total_reports = total_reports + 1,
        scam_reports = scam_reports + 1,
        last_updated = datetime('now')
        WHERE phone_normalized = ?''', (score, score, phone_norm))
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'report_id': report_id,
        'phone': phone_norm,
        'risk_score': score,
        'status': status,
        'scam_type': scam_type,
        'message': 'Report submitted and pending moderation'
    })

@app.route('/api/scan/message', methods=['POST'])
def api_scan_message():
    """Scan a full message and extract risk + domains + sender."""
    message = request.json.get('message', '') if request.json else ''
    if not message:
        return jsonify({'error': 'Message required'}), 400

    sender = extract_sender(message)
    domains = extract_domains(message)
    scam_type = classify_scam_type(message)
    score, signals = compute_risk_score('', message, sender)
    status = get_status(score)

    conn = get_db()
    domain_risks = []
    for d in domains:
        row = conn.execute('SELECT risk_score, source FROM domains WHERE domain = ?', (d,)).fetchone()
        domain_risks.append({
            'domain': d,
            'risk_score': row['risk_score'] if row else 0,
            'source': row['source'] if row else 'unknown',
            'known': bool(row),
        })
        # Boost score if domain is blacklisted
        if row and row['risk_score'] > 50:
            score += 10
            signals.append(f"Blacklisted domain: {d}")

    conn.close()
    status = get_status(min(score, 200))

    return jsonify({
        'risk_score': min(score, 200),
        'status': status,
        'confidence': 'MEDIUM',
        'scam_type': scam_type,
        'sender': sender,
        'domains': domain_risks,
        'signals': signals,
        'message_preview': message[:200],
    })

@app.route('/api/report/<int:report_id>/false-positive', methods=['POST'])
def api_flag_false_positive(report_id):
    conn = get_db()
    conn.execute('''UPDATE reports SET status = 'fp', updated_at = datetime('now')
                    WHERE id = ?''', (report_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Report flagged as false positive'})

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'scamshield-my', 'version': '2.0'})

@app.route('/api/stats')
def api_stats():
    conn = get_db()
    today = datetime.utcnow().strftime('%Y-%m-%d')
    stats = conn.execute('''SELECT
        (SELECT COUNT(*) FROM reports WHERE date(created_at) = ?) as reports_today,
        (SELECT COUNT(*) FROM scores WHERE blacklisted = 1) as blacklisted,
        (SELECT COUNT(*) FROM scores WHERE whitelisted = 1) as whitelisted,
        (SELECT COUNT(*) FROM domains WHERE risk_score > 50) as bad_domains,
        (SELECT COUNT(*) FROM reports WHERE status = 'pending') as pending_review
    ''', (today,)).fetchone()
    conn.close()
    return jsonify(dict(stats))

@app.route('/api/trends')
def api_trends():
    conn = get_db()
    limit = int(request.args.get('limit', 10))
    rows = conn.execute('''SELECT scam_type, COUNT(*) as cnt
        FROM reports WHERE scam_type != 'unknown'
        GROUP BY scam_type ORDER BY cnt DESC LIMIT ?''', (limit,)).fetchall()
    return jsonify([{'type': r['scam_type'], 'count': r['cnt']} for r in rows])

@app.route('/api/blacklist')
def api_blacklist():
    conn = get_db()
    rows = conn.execute('SELECT phone_normalized, reason, added_at FROM blacklist ORDER BY added_at DESC LIMIT 500').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/whitelist')
def api_whitelist():
    conn = get_db()
    rows = conn.execute('SELECT phone_normalized, reason, added_at FROM whitelist ORDER BY added_at DESC LIMIT 500').fetchall()
    return jsonify([dict(r) for r in rows])

# === Moderation / Admin Endpoints ===

def require_moderator():
    """Check if caller is a moderator. In MVP, bypass with header 'x-moderator-key'."""
    key = request.headers.get('x-moderator-key', '')
    valid_keys = os.environ.get('MODERATOR_KEYS', '').split(',')
    valid_keys = [k.strip() for k in valid_keys if k.strip()]
    if not valid_keys:
        return True  # open moderation in beta
    return key in valid_keys

@app.route('/api/moderation/reports/pending')
def api_moderation_pending():
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    rows = conn.execute('''SELECT * FROM reports WHERE status = 'pending'
        ORDER BY risk_score DESC, created_at DESC LIMIT 100''').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/moderation/report/<int:report_id>/approve', methods=['PATCH'])
def api_moderation_approve(report_id):
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    conn.execute('''UPDATE reports SET status = 'approved', updated_at = datetime('now')
                    WHERE id = ?''', (report_id,))
    row = conn.execute('SELECT phone_normalized, scam_type, risk_score, message FROM reports WHERE id = ?', (report_id,)).fetchone()
    if row:
        # Add to blacklist if high risk (>=50)
        if row['risk_score'] >= 50:
            conn.execute('''INSERT OR IGNORE INTO blacklist (phone_normalized, reason, added_by)
                            VALUES (?, 'Approved by moderator', 0)''', (row['phone_normalized'],))
        # Ensure scam_type is set
        if row['scam_type'] == 'unknown' and row['message']:
            scam_type = classify_scam_type(row['message'])
            if scam_type != 'unknown':
                conn.execute('UPDATE reports SET scam_type = ? WHERE id = ?', (scam_type, report_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Report approved'})

@app.route('/api/moderation/report/<int:report_id>/reject', methods=['PATCH'])
def api_moderation_reject(report_id):
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    conn.execute('''UPDATE reports SET status = 'rejected', updated_at = datetime('now')
                    WHERE id = ?''', (report_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Report rejected'})

@app.route('/api/moderation/report/<int:report_id>/dismiss', methods=['PATCH'])
def api_moderation_dismiss(report_id):
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    row = conn.execute('SELECT phone_normalized FROM reports WHERE id = ?', (report_id,)).fetchone()
    if row:
        conn.execute('''UPDATE reports SET status = 'fp', updated_at = datetime('now')
                        WHERE id = ?''', (report_id,))
        conn.execute('DELETE FROM blacklist WHERE phone_normalized = ?', (row['phone_normalized'],))
        conn.execute('''INSERT OR IGNORE INTO whitelist (phone_normalized, reason, added_by)
                        VALUES (?, 'False positive confirmed by moderator', 0)''', (row['phone_normalized'],))
        conn.execute('''UPDATE scores SET whitelisted = 1, blacklisted = 0, current_score = -30
                        WHERE phone_normalized = ?''', (row['phone_normalized'],))
        conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Report dismissed as false positive'})

@app.route('/api/moderation/report/<int:report_id>/escalate', methods=['PATCH'])
def api_moderation_escalate(report_id):
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    conn.execute('''UPDATE reports SET status = 'escalated', updated_at = datetime('now')
                    WHERE id = ?''', (report_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Report escalated for law enforcement'})

@app.route('/api/admin/blacklist', methods=['POST'])
def api_admin_blacklist_add():
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    phone = request.json.get('phone', '').strip() if request.json else ''
    reason = request.json.get('reason', 'Manual addition') if request.json else 'Manual addition'
    if not phone:
        return jsonify({'error': 'Phone required'}), 400
    phone_norm = normalize_number(phone)
    conn = get_db()
    conn.execute('''INSERT OR IGNORE INTO blacklist (phone_normalized, reason, added_by)
                    VALUES (?, ?, 0)''', (phone_norm, reason))
    conn.execute('''UPDATE scores SET blacklisted = 1, current_score = 60 WHERE phone_normalized = ?''', (phone_norm,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Added {phone_norm} to blacklist'})

@app.route('/api/admin/blacklist/<path:phone>')
def api_admin_blacklist_remove(phone):
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    phone_norm = normalize_number(phone)
    conn = get_db()
    conn.execute('DELETE FROM blacklist WHERE phone_normalized = ?', (phone_norm,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Removed {phone_norm} from blacklist'})

@app.route('/api/admin/whitelist', methods=['POST'])
def api_admin_whitelist_add():
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    phone = request.json.get('phone', '').strip() if request.json else ''
    reason = request.json.get('reason', 'Manual addition') if request.json else 'Manual addition'
    if not phone:
        return jsonify({'error': 'Phone required'}), 400
    phone_norm = normalize_number(phone)
    conn = get_db()
    conn.execute('''INSERT OR IGNORE INTO whitelist (phone_normalized, reason, added_by)
                    VALUES (?, ?, 0)''', (phone_norm, reason))
    conn.execute('''UPDATE scores SET whitelisted = 1, current_score = -30 WHERE phone_normalized = ?''', (phone_norm,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Added {phone_norm} to whitelist'})

@app.route('/api/admin/score/<phone>', methods=['PATCH'])
def api_admin_score_override(phone):
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    phone_norm = normalize_number(phone)
    new_score = request.json.get('score', 0) if request.json else 0
    conn = get_db()
    conn.execute('''INSERT OR IGNORE INTO scores (phone_normalized) VALUES (?)''', (phone_norm,))
    conn.execute('''UPDATE scores SET
        override_score = ?, current_score = ?, manual_override = 1,
        last_updated = datetime('now')
        WHERE phone_normalized = ?''', (new_score, new_score, phone_norm))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Score for {phone_norm} set to {new_score}'})

@app.route('/api/admin/reports/bulk', methods=['POST'])
def api_admin_bulk_reports():
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    reports = request.json.get('reports', []) if request.json else []
    conn = get_db()
    count = 0
    for r in reports:
        phone = normalize_number(r.get('phone', ''))
        if not phone:
            continue
        conn.execute('''INSERT INTO reports
            (phone, phone_normalized, message, sender, scam_type, risk_score, status,
             reporter_ip_hash, reporter_email, evidence_urls)
            VALUES (?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?)''',
            (r.get('phone', ''), phone, r.get('message', ''), r.get('sender', ''),
             r.get('scam_type', classify_scam_type(r.get('message', ''))),
             r.get('risk_score', 50), hashlib.sha256(b'admin').hexdigest()[:32],
             r.get('email', ''), r.get('evidence', '')))
        count += 1
        # Update score cache
        conn.execute('''INSERT OR IGNORE INTO scores (phone_normalized) VALUES (?)''', (phone,))
        conn.execute('''UPDATE scores SET
            current_score = ?, last_reported = datetime('now'),
            total_reports = total_reports + 1, scam_reports = scam_reports + 1
            WHERE phone_normalized = ?''', (r.get('risk_score', 50), phone))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Imported {count} reports'})

@app.route('/api/admin/dashboard')
def api_admin_dashboard():
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    today = datetime.utcnow().strftime('%Y-%m-%d')
    stats = conn.execute('''SELECT
        (SELECT COUNT(*) FROM reports WHERE status = 'pending') as pending,
        (SELECT COUNT(*) FROM reports WHERE status = 'approved') as approved,
        (SELECT COUNT(*) FROM reports WHERE status = 'rejected') as rejected,
        (SELECT COUNT(*) FROM reports WHERE status = 'fp') as false_positives,
        (SELECT COUNT(*) FROM reports WHERE status = 'escalated') as escalated,
        (SELECT COUNT(*) FROM reports WHERE date(created_at) = ?) as today_reports,
        (SELECT COUNT(*) FROM blacklist) as blacklist_size,
        (SELECT COUNT(*) FROM whitelist) as whitelist_size
    ''', (today,)).fetchone()
    scam_breakdown = conn.execute('''SELECT scam_type, COUNT(*) as cnt
        FROM reports GROUP BY scam_type ORDER BY cnt DESC LIMIT 10''').fetchall()
    conn.close()
    return jsonify({
        'summary': dict(stats),
        'scam_breakdown': [dict(r) for r in scam_breakdown]
    })

@app.route('/api/admin/reports')
def api_admin_reports():
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    status = request.args.get('status', '')
    limit = int(request.args.get('limit', 100))
    conn = get_db()
    if status:
        rows = conn.execute('''SELECT * FROM reports WHERE status = ?
            ORDER BY created_at DESC LIMIT ?''', (status, limit)).fetchall()
    else:
        rows = conn.execute('''SELECT * FROM reports ORDER BY created_at DESC LIMIT ?''', (limit,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/admin/score/decay', methods=['POST'])
def api_admin_score_decay():
    """Apply daily score decay to all non-whitelisted numbers."""
    if not require_moderator():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    # Decay: reduce score by 5, floor at -50, reset if was manual override
    result = conn.execute('''UPDATE scores SET
        current_score = CASE
            WHEN manual_override = 1 THEN current_score
            WHEN current_score > 20 THEN current_score - 5
            ELSE current_score
        END,
        last_updated = datetime('now')
        WHERE whitelisted = 0''')
    conn.commit()
    updated = result.rowcount
    conn.close()
    return jsonify({'success': True, 'message': f'Decayed scores for {updated} numbers'})

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
