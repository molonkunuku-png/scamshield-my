# ScamShield MY

Malaysia phone scam number checker.

## Deploy
Push to `main` branch on GitHub. Render auto-deploys to `scamshield-my.onrender.com`.

## Local dev
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Visit `http://localhost:10000`

## API

Check a number:
```
GET /api/check?q=01312345678
```

Report a number:
```
POST /api/report
Content-Type: application/x-www-form-urlencoded
phone=01312345678
```

## Carrier guide
- **CLEAN**: 012, 016, 019 (DiGi, Maxis, Celcom — official)
- **DANGER**: 011, 013, 014, 015, 017, 018 (scam-heavy)
- **SUSPICIOUS**: unknown range — verify manually
