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

'''HTTP Authentication

This module implements basic and digest HTTP authentication as described in
HTTP 1.0 and 1.1 specifications:

Basic:
http://www.w3.org/Protocols/HTTP/1.0/draft-ietf-http-spec.html#BasicAA

Digest:

http://www.w3.org/Protocols/HTTP/1.1/spec.html#DigestAA

Do not basic authentication unless you are using SSL or need to work with very
out-dated clients, instead use HTTP digest authentication.

Basically, you just put this module before your WSGI application, and it
takes care of requesting and handling authentication requests.

This code has not been audited by a security expert, please use with
caution (or better yet, report security holes). At this time, this
implementation does not provide for further challenges, nor does it
support Authentication-Info header.  It also uses md5, and an option
to use sha would be a good thing.

'''

import md5, time, random

def digest_password(realm, username, password):
    ''' construct the appropriate hashcode needed for HTTP digest '''
    return md5.new('%s:%s:%s' % (username, realm, password)).hexdigest()

class _Scheme(object):

    _msg = 'This server could not verify that you are authorized to\r\n' \
    'access the document you requested.  Either you supplied the\r\n' \
    'wrong credentials (e.g., bad password), or your browser\r\n' \
    'does not understand how to supply the credentials required.' 

    def __init__(self, realm, authfunc, **kw):
        self.realm, self.authfunc = realm, authfunc
        # WSGI app that sends a 401 response
        self.authresponse = kw.get('response', self._authresponse)
        # Message to return with 401 response
        self.message = kw.get('message', self._msg) 

class _Basic(_Scheme):

    '''Performs HTTP basic authentication.'''      
    
    def __init__(self, realm, authfunc, **kw):
        super(_Basic, self).__init__(realm, authfunc, **kw)

    def _authresponse(self, environ, start_response):
        '''Default HTTP basic authentication response.'''
        start_response('401 Unauthorized', [('content-type', 'text/plain'),
            ('WWW-Authenticate', 'Basic realm="%s"' % self.realm)])
        return [self.message]

    def __call__(self, environ):
        '''This function takes a WSGI environment and authenticates
        the request returning authenticated user or error.
        '''
        authorization = environ.get('HTTP_AUTHORIZATION')
        if authorization is None: return self.authresponse   
        authmeth, auth = authorization.split(' ', 1)
        if authmeth.lower() != 'basic': return self.authresponse
        auth = auth.strip().decode('base64')
        username, password = auth.split(':', 1)
        if self.authfunc(environ, username, password): return username
        return self.authresponse


class _Digest(_Scheme):
    
    '''Performs HTTP digest authentication.'''
    
    def __init__(self, realm, authfunc, **kw):
        super(_Digest, self).__init__(realm, authfunc, **kw)
        self.nonce = dict() # list to prevent replay attacks

    def _authresponse(self, stale = ''):
        ''' builds the authentication error '''
        def coroutine(environ, start_response):
            nonce = md5.new('%s:%s' % (time.time(), random.random())).hexdigest()
            opaque = md5.new('%s:%s' % (time.time(), random.random())).hexdigest()
            self.nonce[nonce] = None
            parts = {'realm':self.realm, 'qop':'auth', 'nonce':nonce, 'opaque':opaque}
            if stale: parts['stale'] = 'true'
            head = ', '.join(['%s="%s"' % (k, v) for (k, v) in parts.items()])
            start_response('401 Unauthorized', [('content-type','text/plain'),
                ('WWW-Authenticate', 'Digest %s' % head)])
            return [self.message]
        return coroutine

    def compute(self, ha1, username, response, method, path, nonce, nc, cnonce, qop):
        ''' computes the authentication, raises error if unsuccessful '''
        if not ha1: return self.authresponse()
        ha2 = md5.new('%s:%s' % (method, path)).hexdigest()
        if qop:
            chk = '%s:%s:%s:%s:%s:%s' % (ha1, nonce, nc, cnonce, qop, ha2)
        else:
            chk = '%s:%s:%s' % (ha1, nonce, ha2)
        if response != md5.new(chk).hexdigest():
            if nonce in self.nonce: del self.nonce[nonce]
            return self.authresponse()
        pnc = self.nonce.get(nonce, '00000000')
        if nc <= pnc:
            if nonce in self.nonce: del self.nonce[nonce]
            return self.authresponse(stale=True)
        self.nonce[nonce] = nc
        return username

    def __call__(self, environ):
        '''This function takes a WSGI environment and authenticates
        the request returning authenticated user or error.
        '''
        method = environ['REQUEST_METHOD']
        fullpath = environ['SCRIPT_NAME'] + environ['PATH_INFO']
        authorization = environ.get('HTTP_AUTHORIZATION')
        if authorization is None: return self.authresponse()
        authmeth, auth = authorization.split(' ', 1)
        if 'digest' != authmeth.lower(): return self.authresponse()
        amap = dict()
        for itm in auth.split(', '):
            k, v = [s.strip() for s in itm.split('=', 1)]
            amap[k] = v.replace('"', '')
        try:
            username = amap['username']
            authpath = amap['uri']
            nonce = amap['nonce']
            realm = amap['realm']
            response = amap['response']
            assert authpath.split('?', 1)[0] in fullpath
            assert realm == self.realm
            qop = amap.get('qop', '')
            cnonce = amap.get('cnonce', '')
            nc = amap.get('nc', '00000000')
            if qop:
                assert 'auth' == qop
                assert nonce and nc
        except:
            return self.authresponse()
        ha1 = self.authfunc(environ, realm, username)
        return self.compute(ha1, username, response, method, authpath, nonce, nc, cnonce, qop)

    
class HTTPAuth(object):

    '''HTTP authentication middleware.'''    
    
    def __init__(self, application, realm, authfunc, scheme, **kw):
        '''
        @param application WSGI application.
        @param realm Identifier for authority requesting authorization.
        @param authfunc For basic authentication, this is a mandatory
            user-defined function which takes a environ, username and
            password for its first three arguments. It should return True
            if the user is authenticated.

            For digest authentication, this is a callback function which
            performs the actual authentication; the signature of this
            callback is:

            authfunc(environ, realm, username) -> hashcode

            This module provides a 'digest_password' helper function which can
            help construct the hashcode; it is recommended that the hashcode
            is stored in a database, not the user's actual password (since you
            only need the hashcode).
        @param scheme HTTP authentication scheme: 'basic' or 'digest'            
        '''
        self.application, self.scheme = application, scheme
        if scheme == 'digest':
            self.authenticate = _Digest(realm, authfunc, **kw)
        elif scheme == 'basic':
            self.authenticate = _Basic(realm, authfunc)

    def __call__(self, env, start_response):
        '''WSGI callable.'''
        user = env.get('REMOTE_USER')
        if user is None:
            result = self.authenticate(env)
            if not isinstance(result, str): return result(env, start_response)
            env['AUTH_TYPE'], env['REMOTE_USER'] = self.scheme, result    
        return self.application(env, start_response)


def basic(realm, authfunc, **kw):
    '''Decorator for HTTP basic middleware.'''
    def decorator(application):
        return HTTPAuth(application, realm, authfunc, 'basic', **kw)
    return decorator

def digest(realm, authfunc, **kw):
    '''Decorator for HTTP digest middleware.'''
    def decorator(application):
        return HTTPAuth(application, realm, authfunc, 'digest', **kw)
    return decorator

__all__ = ['HTTPAuth', 'basic', 'digest', 'digest_password']