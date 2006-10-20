# (c) 2005 Clark C. Evans, Allan Saddi
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com

'''Cookie-Based Authentication.'''

import os, sha, hmac, base64, time, urlparse, cgi
from Cookie import SimpleCookie
from datetime import datetime
from wsgiref.util import request_uri

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

_idchars = ''.join(chr(c) for c in range(0, 255))
_cryptsize = len(hmac.new('x', 'x', sha).hexdigest())

def secretgen():
    ''' returns a 64 byte secret '''
    return ''.join(_idchars[ord(i) % len(_idchars)] for i in os.urandom(64))

def gettime(value):
    return datetime(*time.strptime(value)[0:7])

def extract(environ, empty=False, err=False):
    '''Extracts strings in form data.'''
    qdict = cgi.parse(environ['wsgi.input'], environ, empty, err)
    for key, value in qdict.iteritems():
        if len(value) == 1: qdict[key] = value[0]
    return qdict


_csecret = secretgen()


class _AuthBase(object):

    fieldname = '_CA_'

    def __init__(self, application, authfunc, **kw):
        self.application = application
        self.authfunc = authfunc
        self._secret = kw.get('secret', _csecret)
        self.response = kw.get('response', self._response)
        self.authenticate = kw.get('auth', self.authenticate)
        self.generate = kw.get('generate', self._generate)  
        self.compute = kw.get('compute', self._compute)
        self.age = kw.get('age', 7200)
        self.template = kw.get('template', TEMPLATE)
        self.name = kw.get('fieldname', self.fieldname)
        self.tracker = kw.get('tracker', {})
        self.domain = kw.get('domain')
        self.path, self.comment = kw.get('path', '/'), kw.get('comment')
        self.authlevel = kw.get('authlevel', 1)
        self.timeout = kw.get('timeout', 3600)    

    def _remoteauth(self, environ, value):
        confirm = self.tracker[value]
        username, path = confirm['username'], confirm['path']
        if self.authlevel == 4:
            environ['REMOTE_USER'] = username
            return True
        authstring = base64.urlsafe_b64decode(value)
        current = authstring[:_cryptsize]
        date = gettime(authstring[_cryptsize:].decode('hex'))
        if date > datetime.now().replace(microsecond=0):
            useragent = environ['HTTP_USER_AGENT']                
            raddr = environ['REMOTE_ADDR']
            newvalue = self.compute(username, raddr, path, useragent) 
            if newvalue != current: return False
            environ['REMOTE_USER'] = username
            return True

    def authenticate(self, environ):
        try:
            self._auth(environ)
        except KeyError:
            try:
                if environ['REMOTE_USER'] and environ['AUTH_TYPE'] == self.authtype:
                    return None
            except KeyError:
                return False        

    def _authgen(self, environ):
        username = environ['REMOTE_USER']
        path = environ['SCRIPT_NAME'] + environ['PATH_INFO']
        useragent = environ['HTTP_USER_AGENT']
        raddr = environ['REMOTE_ADDR']
        secret = self.compute(username, raddr, path, useragent)
        timeout = datetime.fromtimestamp(time.time() + self.timeout).ctime()
        value = base64.urlsafe_b64encode(secret + timeout.encode('hex'))
        confirm = {'username':username, 'path':path}
        self.tracker[value] = confirm
        return value

    def _compute(self, username, raddr, path, uagent):
        if self.authlevel == 3 or 4:
            value = self._secret.join([path, username])
        elif self.authlevel == 2:
            value = self._secret.join([username, path, uagent])
        elif self.authlevel == 1:
            value = self._secret.join([raddr, username, uagent, path])
        return hmac.new(self._secret, value, sha).hexdigest()

    def _response(self, environ, start_response):
        start_response('200 OK', [('Content-type', 'text/html')])
        return [self.template % request_uri(environ, 0)]

    def _authenticate(self, environ):
        raise NotImplementedError()

    def _generate(self, environ):
        raise NotImplementedError()
    

class Url(_AuthBase):

    authtype = 'url'    

    def __call__(self, environ, start_response):
        def cookie_response(status, headers, exc_info=None):                        
            headers.append(('Set-Cookie', self.generate(environ)))
            return start_response(status, headers, exc_info)  
        auth = self.authenticate(environ)
        if auth == None:
            return self.application(environ, cookie_response)
        elif not auth:  
            if environ['REQUEST_METHOD'] == 'POST':
                userdata = extract(environ)
                if self.authfunc(userdata):
                    environ['REMOTE_USER'] = userdata['username']
                    environ['AUTH_TYPE'] = 'cookie'
                    environ['REQUEST_METHOD'] = 'GET'
                    environ['CONTENT_LENGTH'] = ''
                    environ['CONTENT_TYPE'] = ''
                    return self.application(environ, cookie_response)
                return self.response(environ, start_response)
            return self.response(environ, start_response)
        return self.application(environ, start_response)     

    def _auth(self, environ):
        qdict = extract(environ)
        return self._remoteauth(environ, qdict[self.name])
        
    def _generate(self, environ):
        authstring = self._authgen(environ)
        url = list(urlparse.urlsplit(request_uri(environ, 0)))
        aqstring = '%s=%s' % (self.cname, authstring)
        if url[3] != '':
            url[3] = '&'.join([aqstring, url[3]])
        else:
            url[3] = aqstring
        return urlparse.urlunsplit(url)
    

class Cookie(_AuthBase):

    authtype = 'cookie'     

    def __call__(self, environ, start_response):
        def cookie_response(status, headers, exc_info=None):                        
            headers.append(('Set-Cookie', self.generate(environ)))
            return start_response(status, headers, exc_info)  
        auth = self.authenticate(environ)
        if auth == None:
            return self.application(environ, cookie_response)
        elif not auth:  
            if environ['REQUEST_METHOD'] == 'POST':
                userdata = extract(environ)
                if self.authfunc(userdata):
                    environ['REMOTE_USER'] = userdata['username']
                    environ['AUTH_TYPE'] = 'cookie'
                    environ['REQUEST_METHOD'] = 'GET'
                    environ['CONTENT_LENGTH'] = ''
                    environ['CONTENT_TYPE'] = ''
                    return self.application(environ, cookie_response)
                return self.response(environ, start_response)
            return self.response(environ, start_response)
        return self.application(environ, start_response)      

    def _auth(self, environ):
        cookies = SimpleCookie(environ['HTTP_COOKIE'])
        scookie = cookies[self.name]
        auth = self._remoteauth(environ, scookie.value)
        if not auth:
            cookie[current]['expires'] = -365*24*60*60
            cookie[current]['max-age'] = 0            
            return False
        return auth

    def _generate(self, environ):
        scookie = SimpleCookie()
        scookie[self.name] = self._authgen(environ)
        scookie[self.name]['path'] = self.path
        scookie[self.name]['max-age'] = self.age
        if self.domain is not None:
            scookie[self.name]['domain'] = self.domain
        if self.comment is not None:
            scookie[self.name]['comment'] = self.comment
        if environ['wsgi.url_scheme'] == 'https':
            scookie[self.name]['secure'] = ''
        return scookie[self.name].OutputString()
        

def cookie(authfunc, **kw):
    '''Decorator for cookie authentication.'''
    def decorator(application):
        return Cookie(application, authfunc, **kw)
    return decorator


__all__ = ['Cookie', 'cookie', 'URL', 'url']