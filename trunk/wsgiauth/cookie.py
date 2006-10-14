# (c) 2005 Clark C. Evans, Allan Saddi
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com

'''Cookie Authentication.'''

import os, sha, hmac, base64, time 
from Cookie import SimpleCookie
from datetime import datetime
from wsgiref.util import request_uri
from util import extract

TEMPLATE ='''<html>
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

_idchars = ''.join(chr(c) for c in range(0, 255))
_cryptsize = len(hmac.new('x', 'x', sha).hexdigest())

def secretgen():
    ''' returns a 64 byte secret '''
    return ''.join(_idchars[ord(c) % len(_idchars)] for c in os.urandom(64))

def gettime(value):
    return datetime(*time.strptime(value)[0:7])

_csecret = secretgen()


class Cookie(object):

    cname = '_CA_'    

    def __init__(self, application, authfunc, **kw):
        self.application = application
        self.authfunc = authfunc
        self._secret = kw.get('secret', _csecret)
        self.authenticate = kw.get('auth', self._authenticate)
        self.response = kw.get('response', self._response)
        self.age = kw.get('age', 7200)
        self.template = kw.get('template', TEMPLATE)
        self.name = kw.get('cookiename', self.cname)
        self.tracker = kw.get('tracker', {})
        self.domain = kw.get('domain')
        self.comment = kw.get('comment')
        self.path = kw.get('path')
        self.timeout = kw.get('timeout', 3600)
        self.everypass = kw.get('everypass', False)
        self._fullurl = None

    def __call__(self, environ, start_response):
        cookies = environ.get('HTTP_COOKIE')        
        if cookies is None:
            return self.response(environ, start_response)
        cookie = SimpleCookie(cookie).get(self.name)
        if cookie is None:
            if environ['REQUEST_METHOD'] == 'POST':
                userdata = extract(environ)
                if self.authfunc(userdata):
                    environ['wsgiauth.userdata'] = userdata
                    environ['AUTH_TYPE'] = 'cookie'
                    environ['REQUEST_METHOD'] = 'GET'
                    environ['REMOTE_USER'] = userdata['username']
                    environ['CONTENT_LENGTH'] = ''
                    environ['CONTENT_TYPE'] = ''                    
                    def cookie_response(status, headers, exc_info=None):                        
                        headers.append(('Set-Cookie', self.cookiegen(environ)))
                        return start_response(status, headers, exc_info)                    
                    return self.application(environ, cookie_response)
                return self.response(environ, start_response)
            return self.response(environ, start_response)
        if self.everypass and not self.authenticate(cookie, environ):
            return self.response(environ, start_response)                
        return self.application(environ, start_response)     
                
    def _authenticate(self, cookie, env):
        secret, confirm = self._secret, self.tracker[value]
        value = base64.urlsafe_b64decode(cookie)
        name, date = value[:_cryptsize], gettime(value[_cryptsize:])
        if date + self.timeout < datetime.now().replace(microsecond=0):            
            uagent, password = env['HTTP_USER_AGENT'], confirm['password']
            path, method = confirm['path'], confirm['method']
            uname, raddr = confirm['username'], env['REMOTE_ADDR']
            cname = Cookie.compute(uname, raddr, path, method, uagent, password) 
            if cname != name:
                cookie[name]['expires'] = -365*24*60*60
                cookie[name]['max-age'] = 0
                return False
            return True
        return False

    def _response(self, environ, start_response):
        start_response('200 OK', [('Content-type', 'text/html')])
        return [self.template % request_uri(environ, 0)]

    def cookiegen(self, environ):
        method, name = environ['REQUEST_METHOD'], self.name
        path = ''.join([environ['SCRIPT_NAME'], environ['PATH_INFO']])
        raddr, uagent = environ['REMOTE_ADDR'], environ['HTTP_USER_AGENT']
        userdata, secret = environ['wsgiauth.userdata'], self._secret
        username, password = userdata['username'], userdata['password']
        crypt = Cookie.compute(uname, raddr, path, method, uageng, password)
        time = datetime.fromtimestamp(time.time() + self.timeout).ctime().encode('hex')
        cname = base64.urlsafe_b64encode(''.join([crypt, time]))
        confirm = {'username':username, 'path':path, 'password':password, 'method':method}
        self.tracker[cname], cookie = confirm, SimpleCookie()
        cookie[name], cookie[name]['path'] = cname, self.path or path
        cookie[name]['max-age'] = self.age
        if self.domain is not None: cookie[name]['domain'] = self.age
        if self.comment is not None: cookie[name]['comment'] = self.comment
        if environ['wsgi.url_scheme'] == 'https': cookie[name]['secure'] = ''
        return cookie[name].OutputString()

    @classmethod
    def compute(secret, uname, raddr, path, method, uageng, password):
        value = secret.join([username, raddr, path,
            sha.new(password).hexdigest(), method, uagent])
        return hmac.new(secret, value, sha).hexdigest()
        

def cookie(authfunc, **kw):
    def decorator(application):
        return Cookie(application, authfunc, **kw)
    return decorator


__all__ = ['Cookie', 'cookie']