import os, time, hmac, sha
from Cookie import SimpleCookie
from wsgiref.util import request_uri
from util import extract
from form import TEMPLATE

_idchars = '-_'.join(chr(c) for c in range(255))

def secretgen():
    return ''.join(_idchars[ord(c) % len(_idchars)] for c in os.urandom(32))

csecret = secretgen()

class Cookie(object):

    cname = '_CA_'    

    def __init__(self, application, authfunc, **kw):
        self.application = application
        self.authfunc = authfunc
        self._secret = kw.get('secret', csecret)
        self.authenticate = kw.get('auth', self._authenticate)
        self.response = kw.get('response', self._response)
        self.age = kw.get('age', 7200)
        self.template = kw.get('template', TEMPLATE)
        self.name = kw.get('cookiename', self.cname)
        self.tracker = kw.get('tracker', {})
        self.domain = kw.get('domain', None)
        self.comment = kw.get('comment', None)
        self.path = kw.get('path', None)
        self._fullurl = None

    def __call__(self, environ, start_response):
        if not self.authenticate(environ):
            if environ['REQUEST_METHOD'] == 'POST':
                userdata = extract(environ)
                if self.authfunc(userdata):
                    environ['wsgiauth.userdata'] = userdata
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
            cookie, secret = cookies[self.name], self._secret
            name = cookie.value
            confirm = self.tracker[name]
            h3 = hmac.HMAC(secret, ''.join([env['HTTP_USER_AGENT'], confirm['password']]), sha).hexdigest()
            h2 = hmac.HMAC(secret, ''.join([confirm['path'], confirm['method']]), sha).hexdigest()
            h1 = hmac.HMAC(secret, ''.join([confirm['username'], env['REMOTE_ADDR']]), sha).hexdigest()
            if hmac.HMAC(secret, ''.join([h2, h1, h3]), sha).hexdigest() != name:
                cookie[name]['expires'] = -365*24*60*60
                cookie[name]['max-age'] = 0
                return False
            return True
        except KeyError:
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
        h1 = hmac.HMAC(secret, ''.join([username, raddr]), sha).hexdigest()
        h2 = hmac.HMAC(secret, ''.join([path, method]), sha).hexdigest()
        h3 = hmac.HMAC(secret, ''.join([uagent, password]), sha).hexdigest()
        cname = hmac.HMAC(secret, ''.join([h2, h1, h3]), sha).hexdigest()
        confirm = {'username':username, 'path':path, 'password':password, 'method':method}
        self.tracker[cname], cookie = confirm, SimpleCookie()
        cookie[name], cookie[name]['path'] = cname, self.path or path
        cookie[name]['max-age'] = self.age
        if self.domain is not None: cookie[name]['domain'] = self.age
        if self.comment is not None: cookie[name]['comment'] = self.comment
        if environ['wsgi.url_scheme'] == 'https': cookie[name]['secure'] = ''
        return cookie[name].OutputString()
        

def cookie(authfunc, **kw):
    def decorator(application):
        return Cookie(application, authfunc, **kw)
    return decorator

__all__ = ['cookie', 'Cookie']