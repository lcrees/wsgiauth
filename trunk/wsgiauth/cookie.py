# (c) 2005 Clark C. Evans, Allan Saddi
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com

'''Cookie-Based Authentication.'''

from Cookie import SimpleCookie
from baseauth import BaseAuth

__all__ = ['Cookie', 'cookie']


def cookie(authfunc, **kw):
    '''Decorator for cookie authentication.'''
    def decorator(application):
        return Cookie(application, authfunc, **kw)
    return decorator


class Cookie(BaseAuth):

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