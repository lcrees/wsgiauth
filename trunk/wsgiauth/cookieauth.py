import sha, os, time, hmac
from Cookie import SimpleCookie
from wsgiref.util import request_uri
from util import extract
from form import TEMPLATE

_idchars = '-_'.join(chr(c) for c in range(255))

def secretgen():
    return ''.join(_idchars[ord(c) % len(_idchars)] for c in os.urandom(32))

class Cookie(object):

    cname = '_COOKIE_AUTH_'    

    def __init__(self, application, authfunc, **kw):
        self.application = application
        self.authfunc = authfunc
        self._secret = kw.get('secret', secretgen())
        self.authenticate = kw.get('auth', self._authenticate)
        self.response = kw.get('response', self._response)
        self.refresh = kw.get('refresh', False)
        self.template = kw.get('template', TEMPLATE)
        self.name = kw.get('cookiename', self.cname)
        self.tracker = kw.get('tracker', {})
        self._fullurl = None

    def __call__(self, environ, start_response):
        if not self.authenticate(environ):
            self._fullurl = request_uri(environ, 1)
            userdata = extract(environ)
            if environ['REQUEST_METHOD'] == 'POST':
                if self.authfunc(userdata):
                    environ['wsgiauth.userdata'] = userdata
                    def cookie_response(status, headers, exc_info=None):                        
                        headers.append(('Set-Cookie', self.cookiegen(environ)))
                        return start_response(status, headers, exc_info)
                    return self.application(environ, cookie_response)
            return self.response(environ, start_response)
        return self.application(environ, start_response)     
                
    def _authenticate(self, env):
        try:
            cookies = SimpleCookie(env['HTTP_COOKIE'])
            cookie = cookies[self.name]
            confirm = self.tracker[cookie.value]
            h3 = sha.sha(''.join([env['REMOTE_ADDR'], env['HTTP_USER_AGENT'], self._secret])).hexdigest()
            h2 = sha.sha(''.join([confirm['path'], self._secret, confirm['method']])).hexdigest()
            h1 = sha.sha(''.join([self._secret, confirm['username'], confirm['password']])).hexdigest()
            return sha.sha(''.join([h2, h1, h3])).hexdigest() == cookie.value
        except KeyError:
            return False

    def _response(self, environ, start_response):
        start_response('200 OK', [('Content-type', 'text/html')])
        return [self.template % self._fullurl]

    def cookiegen(self, environ):
        method = environ['REQUEST_METHOD']
        path = ''.join([environ['SCRIPT_NAME'], environ['PATH_INFO']])
        raddr, uagent = environ['REMOTE_ADDR'], environ['HTTP_USER_AGENT']
        userdata = environ['wsgiauth.userdata']
        username, password = userdata['username'], userdata['password']
        h1 = sha.sha(''.join([self._secret, username, password])).hexdigest()
        h2 = sha.sha(''.join([path, self._secret, method])).hexdigest()
        h3 = sha.sha(''.join([raddr, uagent, self._secret])).hexdigest()
        name = sha.sha(''.join([h2, h1, h3])).hexdigest()
        confirm = {'username':username, 'path':path, 'password':password, 'method':method}
        self.tracker[name] = confirm
        cookie = SimpleCookie()
        cookie[self.name], cookie[self.name]['path'] = name, path
        return cookie[self.name].OutputString()     
        

def cookie(authfunc, **kw):
    def decorator(application):
        return Cookie(application, authfunc, **kw)
    return decorator

__all__ = ['cookie', 'Cookie']