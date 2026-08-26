"""ScamShield MY — Malaysia scam phone number checker."""
import re
import sqlite3
from flask import Flask, jsonify, request, render_template, make_response
from werkzeug.exceptions import NotFound

app = Flask(__name__)

# === Scam / suspicious area codes (Malaysia) ===
# Dangerous: +601, +6013, +6014, +6015, +6017, +6018 (scam-heavy ranges)
# Safe: +6012, +6016, +6019 (official DiGi, Maxis, Celcom)
DANGER_RANGES = {
    '011', '013', '014', '015', '017', '018',  # scam-heavy
}
SAFE_RANGES = {
    '012', '016', '019',
}

def normalize_number(phone):
    """Strip everything except digits and +."""
    phone = re.sub(r'[^\d+]', '', phone)
    return phone

def validate_malaysia_number(phone):
    """
    Validate Malaysian phone number format.
    Returns: (normalized, prefix, area_code, mobile_number, is_valid, status)
    """
    phone = normalize_number(phone)

    # Must start with +60 or 0
    if phone.startswith('+60'):
        phone = phone[3:]
        prefix = '0'
    elif phone.startswith('60'):
        phone = phone[2:]
        prefix = '0'
    elif phone.startswith('0'):
        prefix = '0'
    else:
        return (phone, None, None, None, False, 'INVALID: Not a Malaysian number')

    # Now phone should be like 1X XXXX XXXX (10-11 digits)
    if not phone.isdigit():
        return (phone, prefix, None, None, False, 'INVALID: Contains non-digits')

    if len(phone) < 9 or len(phone) > 11:
        return (phone, prefix, None, None, False, f'INVALID: Wrong length ({len(phone)} digits)')

    # Extract area code (first 3 digits after 0)
    area_code = phone[:3]
    mobile_number = phone[3:]

    is_valid = True
    status = ''

    if area_code in DANGER_RANGES:
        status = 'DANGER: High-risk scam range'
    elif area_code in SAFE_RANGES:
        status = 'CLEAN: Official carrier range'
    else:
        status = 'SUSPICIOUS: Unknown range, verify manually'

    return (prefix + phone, prefix, area_code, mobile_number, is_valid, status)

def init_db():
    conn = sqlite3.connect('scamshield.db', check_same_thread=False)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT UNIQUE,
        status TEXT,
        reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    resp = make_response(render_template('index.html'))
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

@app.route('/api/check')
def api_check():
    phone = request.args.get('q', '').strip()
    if not phone:
        return jsonify({'error': 'Missing query parameter: q'}), 400

    normalized, prefix, area_code, mobile, valid, status = validate_malaysia_number(phone)
    result = {
        'input': phone,
        'normalized': normalized,
        'prefix': prefix,
        'area_code': area_code,
        'mobile_number': mobile,
        'valid': valid,
        'status': status,
    }
    return jsonify(result)

@app.route('/api/report', methods=['POST'])
def api_report():
    phone = request.form.get('phone', '').strip()
    if not phone:
        return jsonify({'error': 'Phone number required'}), 400

    normalized, prefix, area_code, mobile, valid, status = validate_malaysia_number(phone)
    conn = sqlite3.connect('scamshield.db', check_same_thread=False)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO reports (phone, status) VALUES (?, ?)',
                  (normalized, status))
        conn.commit()
        return jsonify({'success': True, 'phone': normalized, 'status': status})
    except sqlite3.IntegrityError:
        c.execute('SELECT status FROM reports WHERE phone = ?', (normalized,))
        row = c.fetchone()
        return jsonify({'success': False, 'duplicate': True, 'phone': normalized, 'status': row[0] if row else 'Unknown'})
    finally:
        conn.close()

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'scamshield-my'})

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
