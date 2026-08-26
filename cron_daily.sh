#!/bin/bash
# Daily cleanup job — score decay + feed refresh
# Runs on Render free tier cron (daily at 02:00 UTC)

cd /home/irene/projects/scamshield-my || exit 1
source .venv/bin/activate 2>/dev/null || python3 -c "
import requests, os
# Trigger the decay and feed refresh endpoints directly
headers = {}
if os.environ.get('MODERATOR_KEYS'):
    headers['x-moderator-key'] = os.environ['MODERATOR_KEYS'].split(',')[0]

base = 'https://scamshield-my-ggvr.onrender.com'
requests.post(f'{base}/api/admin/score/decay', headers=headers)
requests.post(f'{base}/api/admin/feed/refresh', json={'feed': 'all'}, headers=headers)
"
