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

'''Persistent authentication tokens in URL query components.'''

import cgi
from base import BaseAuth
from util import Redirect, requesturl

__all__ = ['URLAuth', 'urlauth']

def urlauth(authfunc, **kw):
    '''Decorator for persistent authentication tokens in URLs.'''
    def decorator(application):
        return URLAuth(application, authfunc, **kw)
    return decorator


class URLAuth(BaseAuth):

    '''Persists authentication tokens in URL query components.'''    

    authtype = 'url'

    def __init__(self, application, authfunc, **kw):
        super(URLAuth, self).__init__(application, authfunc, **kw)
        # Redirect method
        self.redirect = kw.get('redirect', Redirect)

    def __call__(self, environ, start_response):
        # Check authentication
        if not self.authenticate(environ):
            # Request credentials if no authority
            if not self.authorize(environ):
                return self.response(environ, start_response)
            # Embed auth token
            self.generate(environ)
            # Redirect to requested URL with auth token in query string
            redirect = self.redirect(requesturl(environ))
            return redirect(environ, start_response)
        return self.application(environ, start_response)

    def _authenticate(self, environ):
        '''Authenticates a token embedded in a query component.'''
        try:            
            query = cgi.parse_qs(environ['QUERY_STRING'])
            return self._authtoken(environ, query[self.name][0])
        except KeyError:
            return False
        
    def _generate(self, env):
        '''Embeds authentication token in query component.'''
        env['QUERY_STRING'] = '='.join([self.name, self._gettoken(env)])