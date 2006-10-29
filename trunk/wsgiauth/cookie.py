# (c) 2005 Clark C. Evans
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com
#
# Copyright (c) 2005 Allan Saddi <allan@saddi.com>
# Copyright (c) 2006 L. C. Rees.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1.  Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2.  Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# 3.  Neither the name of the Portable Site Information Project nor the names
# of its contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

'''WSGI middleware for persistent authentication tokens in cookies.'''

from Cookie import SimpleCookie
from base import BaseAuth

__all__ = ['Cookie', 'cookie']


def cookie(authfunc, **kw):
    '''Decorator for persistent authentication tokens in cookies.'''
    def decorator(application):
        return Cookie(application, authfunc, **kw)
    return decorator


class Cookie(BaseAuth):

    '''Persists authentication tokens in HTTP cookies.'''    

    authtype = 'cookie'

    def __init__(self, application, authfunc, **kw):
        super(Cookie, self).__init__(application, authfunc, **kw)
        # Cookie domain
        self.domain = kw.get('domain')
        # Cookie age
        self.age = kw.get('age', 7200)
        # Cookie path, comment
        self.path, self.comment = kw.get('path', '/'), kw.get('comment')

    def __call__(self, environ, start_response):
        # Authenticate cookie
        if not self.authenticate(environ):
            # Request credentials if no authority
            if not self.authorize(environ):
                return self.response(environ, start_response)
            # Coroutine to set authetication cookie
            def cookie_response(status, headers, exc_info=None):
                headers.append(('Set-Cookie', self.generate(environ)))
                return start_response(status, headers, exc_info)
            return self.application(environ, cookie_response)
        return self.application(environ, start_response)
        
    def _authenticate(self, environ):
        '''Authenticates a token embedded in a cookie.'''
        try:
            cookies = SimpleCookie(environ['HTTP_COOKIE'])
            scookie = cookies[self.name]
            auth = self._authtoken(environ, scookie.value)
            # Tell user agent to expire cookie if invalid
            if not auth:
                scookie[scookie.value]['expires'] = -365*24*60*60
                scookie[scookie.value]['max-age'] = 0
            return auth
        except KeyError:
            return False

    def _generate(self, environ):
        '''Returns an authentication token embedded in a cookie.'''
        scookie = SimpleCookie()
        scookie[self.name] = self._gettoken(environ)
        scookie[self.name]['path'] = self.path
        scookie[self.name]['max-age'] = self.age
        if self.domain is not None:
            scookie[self.name]['domain'] = self.domain
        if self.comment is not None:
            scookie[self.name]['comment'] = self.comment
        if environ['wsgi.url_scheme'] == 'https':
            scookie[self.name]['secure'] = ''
        return scookie[self.name].OutputString()