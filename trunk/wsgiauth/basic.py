#! /usr/bin/env python
# (c) 2005 Clark C. Evans
#
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com
#
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

'''HTTP Basic Authentication

This module implements basic HTTP authentication as described in
HTTP 1.0:

http://www.w3.org/Protocols/HTTP/1.0/draft-ietf-http-spec.html#BasicAA

Do not use basic authentication unless you are using SSL or need to work
with very out-dated clients, use HTTP digest authentication instead.

Basically, you just put this module before your WSGI application, and it
takes care of requesting and handling authentication requests.

This code has not been audited by a security expert, please use with
caution (or better yet, report security holes).'''

from baseauth import Scheme, HTTPAuth

__all__ = ['basic']

def basic(realm, authfunc, **kw):
    '''Decorator for HTTP basic authentication middleware.'''
    def decorator(application):
        return HTTPAuth(application, realm, authfunc, BasicAuth, **kw)
    return decorator


class BasicAuth(Scheme):

    '''Performs HTTP basic authentication.'''

    authtype = 'basic'

    def _response(self, environ, start_response):
        '''Default HTTP basic authentication response.'''
        start_response('401 Unauthorized', [('content-type', 'text/plain'),
            ('WWW-Authenticate', 'Basic realm="%s"' % self.realm)])
        return [self.message]

    def __call__(self, environ):
        '''This function takes a WSGI environment and authenticates
        the request returning authenticated user or error.
        '''
        authorization = environ.get('HTTP_AUTHORIZATION')
        if authorization is None: return self.response   
        authmeth, auth = authorization.split(' ', 1)
        if authmeth.lower() != 'basic': return self.response
        auth = auth.strip().decode('base64')
        username, password = auth.split(':', 1)
        if self.authfunc(environ, username, password): return username
        return self.response