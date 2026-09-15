import unittest, tempfile, os, io, json, time
os.environ['RAMKA_DB']=tempfile.mktemp(suffix='.db')
os.environ['RAMKA_DEV']='1'
import app
class ServiceTest(unittest.TestCase):
    def request(self,path,method='GET',body=None,cookie='',origin=None):
        data=json.dumps(body or {}).encode(); result={}
        env={'PATH_INFO':'/api/'+path,'REQUEST_METHOD':method,'CONTENT_LENGTH':str(len(data)),'CONTENT_TYPE':'application/json','HTTP_ORIGIN':origin or app.ORIGIN,'HTTP_COOKIE':cookie,'REMOTE_ADDR':'127.0.0.1','wsgi.input':io.BytesIO(data)}
        def start(status,headers): result.update(status=int(status.split()[0]),headers=dict(headers))
        result['data']=json.loads(b''.join(app.application(env,start)));return result
    def test_lifecycle_and_boundaries(self):
        self.assertEqual(self.request('projects')['status'],401)
        cookies=[]
        for i in range(2):
            with app.connect() as db: db.execute('INSERT INTO invites VALUES(?,?,?,?,0)',(app.digest('invite'+str(i)),f'user{i}@example.org',30,time.time()+1000))
            r=self.request('register','POST',{'email':f'user{i}@example.org','password':'a-long-password-123','invite':'invite'+str(i)})
            self.assertEqual(r['status'],200,r);cookies.append(r['headers']['Set-Cookie'].split(';')[0])
        c=cookies[0]
        self.assertEqual(self.request('register','POST',{'email':'user0@example.org','password':'a-long-password-123','invite':'invite0'})['status'],400)
        p={'id':'a','name':'Test','client':'Client','scope':'Included','excluded':'Excluded','price':10000,'rate':500,'hours':8,'actual':2,'expenses':1000,'rounds':2,'changes':[]}
        r=self.request('projects','PUT',{'projects':[p],'revision':0},c);self.assertEqual(r['status'],200,r)
        self.assertEqual(self.request('projects',cookie=cookies[1])['data']['projects'],[])
        self.assertEqual(self.request('projects','PUT',{'projects':[],'revision':0},c)['status'],409)
        self.assertEqual(len(self.request('projects',cookie=c)['data']['projects']),1)
        self.assertEqual(self.request('projects','PUT',{'projects':[],'revision':1},c,origin='https://evil.example')['status'],403)
        p['price']=-1
        self.assertEqual(self.request('projects','PUT',{'projects':[p],'revision':1},c)['status'],400)
        with app.connect() as db: db.execute('UPDATE users SET access_until=0 WHERE email=?',('user0@example.org',))
        self.assertEqual(self.request('projects',cookie=c)['status'],402)
        self.assertEqual(self.request('projects','PUT',{'projects':[],'revision':1},c)['status'],402)
        self.assertEqual(len(self.request('export',cookie=c)['data']['projects']),1)
        self.assertEqual(self.request('logout','POST',{},c)['status'],200)
        self.assertEqual(self.request('me',cookie=c)['status'],401)
        self.assertEqual(self.request('login','POST',{'email':'user1@example.org','password':'wrong-password-123'})['status'],401)
        self.assertEqual(self.request('login','POST',{'email':'user1@example.org','password':'a-long-password-123'})['status'],200)
if __name__=='__main__': unittest.main()
