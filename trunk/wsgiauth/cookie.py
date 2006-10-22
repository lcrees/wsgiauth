# (c) 2005 Clark C. Evans, Allan Saddi
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com

'''Cookie-Based Authentication.'''

import os
import sha
import hmac
import base64
import time
import cgi
from Cookie import SimpleCookie
from datetime import datetime
from urllib import quote

    

__all__ = ['Cookie', 'cookie', 'URLAuth', 'urlauth']

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

def extract(environ, empty=False, err=False):
    '''Extracts strings in form data and returns a dict.

    @param environ WSGI environ
    @param empty Stops on empty fields (default: Fault)
    @param err Stops on errors in fields (default: Fault)
    '''
    formdata = cgi.parse(environ['wsgi.input'], environ, empty, err)    
    # Remove single entries from lists
    for key, value in formdata.iteritems():
        if len(value) == 1: formdata[key] = value[0]   
    return formdata

def request_uri(environ, include_query=1):
    url = environ['wsgi.url_scheme'] + '://'
    if environ.get('HTTP_HOST'):
        url += environ['HTTP_HOST']
    else:
        url += environ['SERVER_NAME']
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                url += ':' + environ['SERVER_PORT']
        else:
            if environ['SERVER_PORT'] != '80':
                url += ':' + environ['SERVER_PORT']
    url += quote(environ.get('SCRIPT_NAME',''))
    url += quote(environ.get('PATH_INFO',''))
    if include_query and environ.get('QUERY_STRING'):
        url += '?' + environ['QUERY_STRING']
    return url

def cookie(authfunc, **kw):
    '''Decorator for cookie authentication.'''
    def decorator(application):
        return Cookie(application, authfunc, **kw)
    return decorator

def urlauth(authfunc, **kw):
    '''Decorator for url authentication.'''
    def decorator(application):
        return URLAuth(application, authfunc, **kw)
    return decorator

# Fallback secret
_secret = getsecret()


class Redir(object):

    def __init__(self, location):
        self.location = location

    def __call__(self, environ, start_response):
        start_response('302 Found', [('content-type', 'text/html'),
            ('location', self.location)])
        return ['<html>\n<head><title>Redirecting to %s</title><head>\n' \
        '<body>You are being redirected to <a href="%s">%s</a>' \
        '</body></html>\n' % (self.location, self.location, self.location)]


class _AuthBase(object):

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
        if environ.get('wsgiauth.persist') is not None:
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


class URLAuth(_AuthBase):

    authtype = 'url'

    def __call__(self, environ, start_response):
        auth = self.authenticate(environ)
        if not auth:
            authority = self.authorize(environ)
            if not authority: return self.response(environ, start_response)
            redirect = Redir(self.generate(environ))
            return redirect(environ, start_response)
        return self.application(environ, start_response)     

    def _validate(self, environ):
        try:
            query = cgi.parse_qs(environ['QUERY_STRING'])        
            return self._authid(environ, query[self.name][0])
        except KeyError:
            return False
        
    def _generate(self, environ):
        authstring = self._getid(environ)
        aqstring = '%s=%s' % (self.name, authstring)
        environ['QUERY_STRING'] = aqstring
        return request_uri(environ)
    

class Cookie(_AuthBase):

    authtype = 'cookie'

    def __init__(self, application, authfunc, **kw):
        super(Cookie, self).__init__(application, authfunc, **kw)
        self.domain = kw.get('domain')
        self.age = kw.get('age', 7200)
        self.path, self.comment = kw.get('path', '/'), kw.get('comment')

    def __call__(self, environ, start_response):             
        auth = self.authenticate(environ)
        if not auth:
            authority = self.authorize(environ)
            if not authority: return self.response(environ, start_response)
            def cookie_response(status, headers, exc_info=None):
                headers.append(('Set-Cookie', self.generate(environ)))
                return start_response(status, headers, exc_info)   
            return self.application(environ, cookie_response)
        return self.application(environ, start_response)
        
    def _validate(self, environ):
        try:
            cookies = SimpleCookie(environ['HTTP_COOKIE'])
            scookie = cookies[self.name]
            auth = self._authid(environ, scookie.value)
            if not auth:
                scookie[scookie.value]['expires'] = -365*24*60*60
                scookie[scookie.value]['max-age'] = 0
            return auth
        except KeyError:
            return False

    def _generate(self, environ):
        scookie = SimpleCookie()
        scookie[self.name] = self._getid(environ)
        scookie[self.name]['path'] = self.path
        scookie[self.name]['max-age'] = self.age
        if self.domain is not None:
            scookie[self.name]['domain'] = self.domain
        if self.comment is not None:
            scookie[self.name]['comment'] = self.comment
        if environ['wsgi.url_scheme'] == 'https':
            scookie[self.name]['secure'] = ''
        return scookie[self.name].OutputString()