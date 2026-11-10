"""Create a balanced synthetic CSV only for pipeline smoke tests; not a scientific benchmark."""
import csv,random
from datetime import date,timedelta
from pathlib import Path
random.seed(42)
phish_subjects=['Action required: verify your mailbox','Invoice overdue — payment today','Security alert: account locked','Updated bank details required','Document shared with you']
phish_bodies=['Your account will be suspended unless you sign in immediately at {url}.','Please review the attached invoice and confirm payment to the new bank account.','We detected unusual activity. Verify your password within 24 hours using {url}.','This confidential payroll request must be completed urgently. Do not call; reply here.','Open the secure document and authenticate your account at {url}.']
legit_subjects=['Weekly project status update','Meeting agenda for tomorrow','University timetable published','Your monthly service statement','Team documentation shared']
legit_bodies=['Hello team, attached is the agenda for our scheduled meeting. Please review it before the discussion.','The weekly project update is ready. You can access the shared workspace using the bookmark you already have.','Your statement is available in the usual customer portal. Contact support using the phone number on your card.','The department timetable has been published on the official university website.','Thank you for your contribution. No action is required; contact your manager if you have questions.']
urls=['http://198.51.100.23/login','http://secure-account-check.example.invalid/verify','https://bit.ly/example-check','http://paypa1-login.example.invalid/auth','https://files-share.example.invalid/document']
rows=[]; start=date(2024,1,1)
for i in range(1200):
    label='phishing' if i%2==0 else 'legitimate'; day=i//12; group=f'week-{day//12:03d}'
    if label=='phishing': subject=random.choice(phish_subjects); body=random.choice(phish_bodies).format(url=random.choice(urls))
    else: subject=random.choice(legit_subjects); body=random.choice(legit_bodies)
    # Add harmless variation to exercise tokenization while retaining explicit synthetic status.
    body += ' Reference: '+str(random.randint(10000,99999))+'.'
    rows.append({'subject':subject,'body':body,'label':label,'group_id':group,'date':(start+timedelta(days=day)).isoformat(),'source':'PhishGuard synthetic smoke generator','synthetic':'true','license':'generated-not-third-party'})
out=Path(__file__).resolve().parents[1]/'datasets'/'synthetic_smoke.csv';out.parent.mkdir(exist_ok=True)
with out.open('w',newline='',encoding='utf-8') as f:
    w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
print(f'Created {len(rows)} SYNTHETIC rows at {out}. Use only to verify the training pipeline; do not report as real-world benchmark.')
