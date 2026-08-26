#!/usr/bin/env python3
"""Daily cron job: score decay + feed refresh."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, get_db

def run_decay():
    """Daily score decay for non-whitelisted numbers."""
    with app.app_context():
        conn = get_db()
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
        print(f"Decayed scores for {updated} numbers")
        conn.close()

def run_feed_refresh():
    """Refresh feeds (placeholder for real fetchers)."""
    feeds = [
        ('MCMC Spam Numbers', 'https://www.mcmc.gov.my/en/activities/spam-sms-numbers'),
        ('Bank Negara Scam Alerts', 'https://www.bnm.gov.my/documents/10121/1277436/Consumer%20Advisory.pdf'),
        ('PDRM Cyber Crime', 'https://www.rmp.gov.my/'),
    ]
    conn = get_db()
    for name, url in feeds:
        conn.execute('UPDATE feeds SET last_refreshed = datetime("now") WHERE url = ?', (url,))
    conn.commit()
    conn.close()
    print(f"Refreshed {len(feeds)} feeds")

if __name__ == '__main__':
    print("Running daily maintenance...")
    run_decay()
    run_feed_refresh()
    print("Daily maintenance complete.")
