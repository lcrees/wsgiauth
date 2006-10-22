import os
import sha
import hmac
import base64
import time
import cgi
from datetime import datetime
from urllib import quote
try:
    from wsgiref.util import request_uri
except ImportError:
    from util import request_uri
from util import extract
    

__all__ = ['BaseAuth']

# Default template
TEMPLATE = '''<html>
 <head><title>Please Login</title></head>
 <body>
  <h1>Please Login</h1>
  <form action="%s" method="post">
   <dl>
    <dt>Username:</dt>
    <dd><input type="text" name="username"></dd>
    <dt>Password:</dt>
    <dd><input type="password" name="password"></dd>
   </dl>
   <input type="submit" name="authform" />
   <hr />
  </form>
 </body>
</html>'''

# ASCII chars
_chars = ''.join(chr(c) for c in range(0, 255))
# Size of HMAC sign w/ SHA as hash
_cryptsize = len(hmac.new('x', 'x', sha).hexdigest())

def getsecret():
    '''Returns a 64 byte secret.'''
    return ''.join(_chars[ord(i) % len(_chars)] for i in os.urandom(64))

def gettime(date):
    '''Returns a datetime object from a date string.

    @param date Date/time string
    '''
    return datetime(*time.strptime(date)[0:7])

# Fallback secret
_secret = getsecret()


class BaseAuth(object):

    fieldname = '_CA_'
    authtype = None

    def __init__(self, application, authfunc, **kw):
        self.application = application
        self.authfunc = authfunc
        self._secret = kw.get('secret', _secret)        
        self.authenticate = kw.get('authenticate', self._authenticate)
        self.authorize = kw.get('authorize', self._authorize)
        self.generate = kw.get('generate', self._generate) 
        self.compute = kw.get('compute', self._compute)
        self.response = kw.get('response', self._response)        
        self.template = kw.get('template', TEMPLATE)
        self.name = kw.get('name', self.fieldname)
        self.tracker = kw.get('tracker', {})        
        self.authlevel = kw.get('authlevel', 1)
        self.timeout = kw.get('timeout', 3600)
        self.namevar = kw.get('namevar', 'username')

    def _authenticate(self, environ):
        return self._validate(environ)
        
    def _authorize(self, environ):
        if environ.get('REMOTE_USER') is not None:
            return True
        elif environ['REQUEST_METHOD'] == 'POST':
            userdata = extract(environ)
            if self.authfunc(userdata):
                environ['REMOTE_USER'] = userdata[self.namevar]                
                environ['REQUEST_METHOD'] = 'GET'
                environ['CONTENT_LENGTH'] = ''
                environ['CONTENT_TYPE'] = ''
                return True
            return False
        return False            

    def _getid(self, environ):
        username = environ['REMOTE_USER']
        path = environ['SCRIPT_NAME'] + environ['PATH_INFO']
        useragent = environ['HTTP_USER_AGENT']
        raddr = environ['REMOTE_ADDR']
        server = environ['SERVER_NAME']
        id = self.compute(username, raddr, server, path, useragent)
        timeout = datetime.fromtimestamp(time.time() + self.timeout).ctime()
        value = base64.urlsafe_b64encode(id + timeout.encode('hex'))
        confirm = {'username':username, 'path':path}
        self.tracker[value] = confirm
        return value

    def _authid(self, environ, value):
        confirm = self.tracker[value]
        username, path = confirm['username'], confirm['path']
        if self.authlevel == 4:
            environ['REMOTE_USER'] = username
            environ['AUTH_TYPE'] = self.authtype
            return True
        authstring = base64.urlsafe_b64decode(value)
        current = authstring[:_cryptsize]
        date = gettime(authstring[_cryptsize:].decode('hex'))
        if date > datetime.now().replace(microsecond=0):
            useragent = environ['HTTP_USER_AGENT']                
            raddr = environ['REMOTE_ADDR']
            server = environ['SERVER_NAME']
            newvalue = self.compute(username, raddr, server, path, useragent) 
            if newvalue != current: return False
            environ['REMOTE_USER'] = username
            environ['AUTH_TYPE'] = self.authtype
            return True        

    def _compute(self, username, raddr, server, path, uagent):
        if self.authlevel == 3 or 4:
            value = self._secret.join([path, username])
        elif self.authlevel == 2:
            value = self._secret.join([username, path, server, uagent])
        elif self.authlevel == 1:
            value = self._secret.join([raddr, username, server, uagent, path])
        return hmac.new(self._secret, value, sha).hexdigest()

    def _response(self, environ, start_response):
        start_response('200 OK', [('Content-type', 'text/html')])
        return [self.template % request_uri(environ, 0)]

    def _validate(self, environ):
        raise NotImplementedError()

    def _generate(self, environ):
        raise NotImplementedError()