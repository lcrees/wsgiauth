import os
import sha
import hmac
import base64
import time
from datetime import datetime
try:
    from wsgiref.util import request_uri
except ImportError:
    from util import request_uri
from util import extract
    

__all__ = ['BaseAuth', 'Scheme', 'HTTPAuth']

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


class Scheme(object):

    _msg = 'This server could not verify that you are authorized to\r\n' \
    'access the document you requested.  Either you supplied the\r\n' \
    'wrong credentials (e.g., bad password), or your browser\r\n' \
    'does not understand how to supply the credentials required.' 

    def __init__(self, realm, authfunc, **kw):
        self.realm, self.authfunc = realm, authfunc
        # WSGI app that sends a 401 response
        self.authresponse = kw.get('response', self._authresponse)
        # Message to return with 401 response
        self.message = kw.get('message', self._msg)    


class HTTPAuth(object):

    '''HTTP authentication middleware.'''    
    
    def __init__(self, application, realm, authfunc, scheme, **kw):
        '''
        @param application WSGI application.
        @param realm Identifier for authority requesting authorization.
        @param authfunc For basic authentication, this is a mandatory
            user-defined function which takes a environ, username and
            password for its first three arguments. It should return True
            if the user is authenticated.

            For digest authentication, this is a callback function which
            performs the actual authentication; the signature of this
            callback is:

            authfunc(environ, realm, username) -> hashcode

            This module provides a 'digest_password' helper function which can
            help construct the hashcode; it is recommended that the hashcode
            is stored in a database, not the user's actual password (since you
            only need the hashcode).
        @param scheme HTTP authentication scheme: Basic or Digest            
        '''
        self.application = application
        self.authenticate = scheme(realm, authfunc, **kw)
        self.scheme = scheme.authtype

    def __call__(self, environ, start_response):
        user = environ.get('REMOTE_USER')
        if user is None:
            result = self.authenticate(env)
            if not isinstance(result, str):
                return result(environ, start_response)
            environ['AUTH_TYPE'], environ['REMOTE_USER'] = self.scheme, result    
        return self.application(environ, start_response)    