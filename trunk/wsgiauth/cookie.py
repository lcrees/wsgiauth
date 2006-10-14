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
        self.cookiegen = kw.get('cookiegen', self._cookiegen)
        self.compute = kw.get('compute', self._compute)
        self.age = kw.get('age', 7200)
        self.template = kw.get('template', TEMPLATE)
        self.name = kw.get('cookiename', self.cname)
        self.tracker = kw.get('tracker', {})
        self.domain = kw.get('domain')
        self.path, self.comment = kw.get('path'), kw.get('comment')
        self.authlevel = kw.get('authlevel', 1)
        self.timeout = kw.get('timeout', 3600)
        self._fullurl = None

    def __call__(self, environ, start_response):
        if not self.authenticate(environ):
            if environ['REQUEST_METHOD'] == 'POST':
                userdata = extract(environ)
                if self.authfunc(userdata):
                    environ['wsgiauth.userdata'] = userdata
                    environ['AUTH_TYPE'] = 'cookie'
                    environ['REQUEST_METHOD'] = 'GET'
                    environ['CONTENT_LENGTH'] = ''
                    environ['CONTENT_TYPE'] = ''                    
                    def cookie_response(status, headers, exc_info=None):                        
                        headers.append(('Set-Cookie', self.cookiegen(environ)))
                        return start_response(status, headers, exc_info)                    
                    return self.application(environ, cookie_response)
                return self.response(environ, start_response)
            return self.response(environ, start_response)
        return self.application(environ, start_response)     
                
    def _authenticate(self, env):
        try:
            cookies = SimpleCookie(env['HTTP_COOKIE'])
            cookie = cookies[self.name]            
            confirm = self.tracker[cookie.value]
            if self.authlevel == 4: return True
            value = base64.urlsafe_b64decode(cookie.value)            
            cvalue = value[:_cryptsize]
            date = gettime(value[_cryptsize:].decode('hex'))
            if date > datetime.now().replace(microsecond=0):
                username = confirm['username']                            
                password = confirm['password']                
                path = confirm['path']
                method = confirm['method']
                useragent = env['HTTP_USER_AGENT']                
                ipaddr = env['REMOTE_ADDR']
                nvalue = self.compute(username, ipaddr, path, method, useragent, password) 
                if nvalue != cvalue:
                    cookie[cvalue]['expires'] = -365*24*60*60
                    cookie[cvalue]['max-age'] = 0
                    return False
                return True
            return False
        except KeyError:
            return False

    def _response(self, environ, start_response):
        start_response('200 OK', [('Content-type', 'text/html')])
        return [self.template % request_uri(environ, 0)]

    def _cookiegen(self, environ):
        userdata = environ['wsgiauth.userdata']
        username = userdata['username']
        password = userdata['password']
        path = environ['SCRIPT_NAME'] + environ['PATH_INFO']
        method = environ['REQUEST_METHOD']
        useragent = environ['HTTP_USER_AGENT']
        ipaddr = environ['REMOTE_ADDR']
        hash = self.compute(username, ipaddr, path, method, useragent, password)
        timeout = datetime.fromtimestamp(time.time() + self.timeout).ctime()
        value = base64.urlsafe_b64encode(hash + timeout.encode('hex'))
        confirm = {'username':username, 'path':path, 'password':password, 'method':method}
        self.tracker[value] = confirm 
        cookie = SimpleCookie()
        cookie[self.name] = value
        cookie[self.name]['path'] = self.path or path
        cookie[self.name]['max-age'] = self.age
        if self.domain is not None:
            cookie[self.name]['domain'] = self.age
        if self.comment is not None:
            cookie[self.name]['comment'] = self.comment
        if environ['wsgi.url_scheme'] == 'https':
            cookie[self.name]['secure'] = ''
        return cookie[self.name].OutputString()

    def _compute(self, uname, raddr, path, method, uagent, password):
        passhash = sha.new(password).hexdigest()
        if self.authlevel == 3 or 4:
            value = self._secret.join([path, uname])
        elif self.authlevel == 2:
            value = self._secret.join([uname, path, passhash, method])
        elif self.authlevel == 1:
            value = self._secret.join([uname, raddr, path, passhash, method, uagent])
        return hmac.new(self._secret, value, sha).hexdigest()
        

def cookie(authfunc, **kw):
    '''Decorator for cookie authentication.'''
    def decorator(application):
        return Cookie(application, authfunc, **kw)
    return decorator


__all__ = ['Cookie', 'cookie']