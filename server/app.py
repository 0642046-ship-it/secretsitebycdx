"""RAMKA: single-origin WSGI service, SQLite, invite-only paid access."""
import os, json, sqlite3, time, secrets, hashlib, hmac, re, math
from pathlib import Path
from http.cookies import SimpleCookie
DB = os.environ.get('RAMKA_DB', '/data/ramka.db')
ORIGIN = os.environ.get('RAMKA_ORIGIN', 'http://localhost:8000').rstrip('/')
STATIC = Path(__file__).resolve().parent.parent
DEV = os.environ.get('RAMKA_DEV') == '1'

def connect():
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, access_until REAL NOT NULL);
CREATE TABLE IF NOT EXISTS invites(code TEXT PRIMARY KEY, email TEXT NOT NULL, days INTEGER NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id), expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS workspaces(user_id INTEGER PRIMARY KEY REFERENCES users(id), payload TEXT NOT NULL DEFAULT '[]', revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS rate_limits(key TEXT PRIMARY KEY, window REAL NOT NULL, count INTEGER NOT NULL);''')
    return db

def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def password_hash(p, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + ':' + hashlib.pbkdf2_hmac('sha256', p.encode(), salt.encode(), 600000).hex()
class Error(Exception):
    def __init__(self, status, message): self.status, self.message = status, message

def validate_projects(items):
    if not isinstance(items, list) or len(items)>100: raise Error(400,'Максимум 100 проектов')
    ids=set()
    def text(obj,key,maxlen,required=False):
        s=obj.get(key)
        if not isinstance(s,str) or len(s)>maxlen or (required and not s.strip()): raise Error(400,'Некорректное поле: '+key)
        return s
    def number(obj,key,maxval):
        n=obj.get(key)
        if type(n) not in (int,float) or not math.isfinite(n) or n<0 or n>maxval: raise Error(400,'Некорректное число: '+key)
        return n
    result=[]
    for p in items:
        if not isinstance(p,dict): raise Error(400,'Некорректный проект')
        out={k:text(p,k,160 if k in ['name','client'] else 6000,k in ['name','client','id']) for k in ['id','name','client','scope','excluded']}
        if len(out['id'])>80 or out['id'] in ids: raise Error(400,'Повторяющийся ID')
        ids.add(out['id'])
        for k in ['price','expenses','rate','hours','actual','rounds']: out[k]=number(p,k,{'rate':1e6,'hours':1e5,'actual':1e5,'rounds':100}.get(k,1e9))
        if out['rounds']%1: raise Error(400,'Раунды должны быть целыми')
        changes=p.get('changes')
        if not isinstance(changes,list) or len(changes)>200: raise Error(400,'Максимум 200 изменений в проекте')
        out['changes']=[]; cids=set()
        for c in changes:
            if not isinstance(c,dict): raise Error(400,'Некорректное изменение')
            item={k:text(c,k,6000 if k=='description' else 160,True) for k in ['id','title','description']}
            if item['id'] in cids: raise Error(400,'Повторяющийся ID изменения')
            cids.add(item['id'])
            item.update(hours=number(c,'hours',1e5),price=number(c,'price',1e9),status=c.get('status'))
            if item['status'] not in ['pending','approved','rejected']: raise Error(400,'Некорректный статус')
            out['changes'].append(item)
        result.append(out)
    return result

def application(env, start_response):
    extra=[]; db=None; status=200; content_type='application/json; charset=utf-8'
    try:
        path=env.get('PATH_INFO','/'); method=env.get('REQUEST_METHOD','GET')
        if path=='/api/health': result={'service':'ramka'}
        elif not path.startswith('/api/'):
            if method!='GET': raise Error(405,'Метод не поддерживается')
            files={'/':('index.html','text/html; charset=utf-8'),'/index.html':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
            if path not in files: raise Error(404,'Не найдено')
            name,content_type=files[path]; result=(STATIC/name).read_bytes()
            if name=='index.html': result=result.replace(b'name="ramka-mode" content="demo"',b'name="ramka-mode" content="server"')
        else:
            if not DEV and not ORIGIN.startswith('https://'): raise Error(503,'Настройте HTTPS-адрес сервиса')
            db=connect(); body={}
            if method not in ['GET','HEAD']:
                if env.get('HTTP_ORIGIN')!=ORIGIN: raise Error(403,'Недопустимый источник запроса')
                if env.get('CONTENT_TYPE','').split(';')[0]!='application/json': raise Error(415,'Требуется JSON')
                try: length=int(env.get('CONTENT_LENGTH','0'))
                except ValueError: raise Error(400,'Некорректная длина запроса')
                if not 0<length<=2000000: raise Error(413,'Максимум 2 МБ')
                try: body=json.loads(env['wsgi.input'].read(length))
                except (ValueError,UnicodeError): raise Error(400,'Некорректный JSON')
                if not isinstance(body,dict): raise Error(400,'Ожидается объект')
            now=time.time()
            if path in ['/api/register','/api/login'] and method=='POST':
                email=str(body.get('email','')).strip().lower(); password=body.get('password','')
                if not re.fullmatch(r'[^\s@]{1,100}@[^\s@]{1,100}\.[^\s@]{1,40}',email): raise Error(400,'Проверь email')
                if not isinstance(password,str) or not 12<=len(password)<=128: raise Error(400,'Пароль: от 12 до 128 символов')
                db.execute('BEGIN IMMEDIATE')
                for key in ['ip:'+env.get('REMOTE_ADDR','unknown'),'email:'+email]:
                    row=db.execute('SELECT * FROM rate_limits WHERE key=?',(key,)).fetchone()
                    if row and now-row['window']<900 and row['count']>=(200 if key.startswith('ip:') else 20):
                        db.commit(); raise Error(429,'Слишком много попыток. Повтори через 15 минут')
                    if row and now-row['window']<900: db.execute('UPDATE rate_limits SET count=count+1 WHERE key=?',(key,))
                    else: db.execute('INSERT OR REPLACE INTO rate_limits VALUES(?,?,1)',(key,now))
                db.execute('DELETE FROM rate_limits WHERE window<?',(now-86400,)); db.commit()
                if path=='/api/register':
                    db.execute('BEGIN IMMEDIATE')
                    code=digest(str(body.get('invite','')))
                    invitation=db.execute('SELECT * FROM invites WHERE code=? AND email=? AND used=0 AND expires>?',(code,email,now)).fetchone()
                    if not invitation: raise Error(400,'Приглашение недействительно или уже использовано')
                    try: cur=db.execute('INSERT INTO users(email,password,access_until) VALUES(?,?,?)',(email,password_hash(password),now+invitation['days']*86400))
                    except sqlite3.IntegrityError: raise Error(400,'Аккаунт уже существует. Используй вход')
                    user_id=cur.lastrowid
                    db.execute('INSERT INTO workspaces(user_id) VALUES(?)',(user_id,));db.execute('UPDATE invites SET used=1 WHERE code=?',(code,))
                else:
                    u=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                    stored=u['password'] if u else '0'*32+':'+'0'*64
                    if not hmac.compare_digest(password_hash(password,stored.split(':')[0]),stored): raise Error(401,'Неверный email или пароль')
                    user_id=u['id']
                token=secrets.token_urlsafe(32)
                db.execute('DELETE FROM sessions WHERE expires<?',(now,));db.execute('INSERT INTO sessions VALUES(?,?,?)',(digest(token),user_id,now+7*86400));db.commit()
                extra.append(('Set-Cookie','ramka_session='+token+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800'+('' if DEV else '; Secure')))
                result={'ok':True}
            else:
                cookies=SimpleCookie();cookies.load(env.get('HTTP_COOKIE',''))
                token=cookies['ramka_session'].value if 'ramka_session' in cookies else ''
                u=db.execute('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=? AND s.expires>?',(digest(token),now)).fetchone()
                if not u: raise Error(401,'Войди в аккаунт')
                if path=='/api/logout' and method=='POST':
                    db.execute('DELETE FROM sessions WHERE token=?',(digest(token),));db.commit();extra.append(('Set-Cookie','ramka_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'+('' if DEV else '; Secure')));result={'ok':True}
                elif path=='/api/me' and method=='GET': result={'email':u['email'],'access_until':u['access_until']}
                elif path=='/api/export' and method=='GET': result={'projects':json.loads(db.execute('SELECT payload FROM workspaces WHERE user_id=?',(u['id'],)).fetchone()[0])}
                elif path=='/api/projects':
                    if u['access_until']<=now: raise Error(402,'Срок доступа закончился. Продли подписку у владельца сервиса')
                    if method=='GET':
                        r=db.execute('SELECT * FROM workspaces WHERE user_id=?',(u['id'],)).fetchone();result={'projects':json.loads(r['payload']),'revision':r['revision']}
                    elif method=='PUT':
                        projects=validate_projects(body.get('projects'));revision=body.get('revision')
                        if type(revision)!=int or revision<0: raise Error(400,'Некорректная версия данных')
                        cur=db.execute('UPDATE workspaces SET payload=?,revision=revision+1 WHERE user_id=? AND revision=?',(json.dumps(projects,ensure_ascii=False),u['id'],revision))
                        if cur.rowcount!=1: raise Error(409,'Данные изменены в другой вкладке. Загружена последняя версия; повтори изменение')
                        db.commit();result={'revision':revision+1}
                    else: raise Error(405,'Метод не поддерживается')
                else: raise Error(404,'Не найдено')
    except Error as e: status=e.status;result={'error':e.message}
    except Exception:
        status=500;result={'error':'Ошибка сервера. Данные не изменены'}
    finally:
        if db: db.close()
    payload=result if isinstance(result,bytes) else json.dumps(result,ensure_ascii=False,allow_nan=False).encode()
    reasons={200:'OK',400:'Bad Request',401:'Unauthorized',402:'Payment Required',403:'Forbidden',404:'Not Found',405:'Method Not Allowed',409:'Conflict',413:'Payload Too Large',415:'Unsupported Media Type',429:'Too Many Requests',500:'Internal Server Error',503:'Service Unavailable'}
    headers=[('Content-Type',content_type),('Content-Length',str(len(payload))),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),('X-Frame-Options','DENY'),('Referrer-Policy','no-referrer'),('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]+extra
    start_response(str(status)+' '+reasons[status],headers)
    return [payload]

if __name__=='__main__':
    from wsgiref.simple_server import make_server
    print('Development server: http://localhost:8000')
    make_server('127.0.0.1',8000,application).serve_forever()
