"""Local operator CLI. No public admin endpoint and no payment self-activation."""
import argparse, secrets, time, getpass
from app import connect,digest,password_hash
p=argparse.ArgumentParser();p.add_argument('action',choices=['invite','extend','revoke','reset-password']);p.add_argument('email');p.add_argument('--days',type=int,default=30);args=p.parse_args()
if not 1<=args.days<=366: p.error('--days must be 1..366')
email=args.email.strip().lower()
with connect() as db:
    if args.action=='invite':
        code=secrets.token_urlsafe(24)
        db.execute('INSERT INTO invites VALUES(?,?,?,?,0)',(digest(code),email,args.days,time.time()+7*86400))
        print('Invitation (expires in 7 days, share privately with this email owner): '+code)
    else:
        u=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        if not u: p.error('Account not found')
        if args.action=='extend': db.execute('UPDATE users SET access_until=? WHERE id=?',(max(time.time(),u['access_until'])+args.days*86400,u['id']))
        elif args.action=='revoke':
            db.execute('UPDATE users SET access_until=0 WHERE id=?',(u['id'],))
            db.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
        else:
            password=getpass.getpass('New password (12..128 characters): ')
            if not 12<=len(password)<=128: p.error('Invalid password length')
            db.execute('UPDATE users SET password=? WHERE id=?',(password_hash(password),u['id']))
            db.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
        print('Done')
