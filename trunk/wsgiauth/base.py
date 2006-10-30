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

'''Base authentication classes.'''

import os
import sha
import hmac
import base64
import time
from urllib import quote
from datetime import datetime
from util import extract, getpath, Response
    

__all__ = ['BaseAuth', 'Scheme', 'HTTPAuth']

# Default authorization response template
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

# Fallback secret
_secret = getsecret()
# Fallback tracker
_tracker = dict()


class BaseAuth(object):

    '''Base class for authentication persisting.'''

    fieldname = '_CA_'
    authtype = None

    def __init__(self, application, authfunc, **kw):
        self.application = application
        # Custom authorization function
        self.authfunc = authfunc
        # Secret signing key
        self._secret = kw.get('secret', _secret)
        # Authorization response
        self.response = kw.get('response', Response(template=TEMPLATE))
        # Token name
        self.name = kw.get('name', self.fieldname)
        # Token tracking store
        self.tracker = kw.get('tracker', _tracker)
        # Per request authentication level (1-4)
        self.authlevel = kw.get('authlevel', 1)
        # Authentication session timeout
        self.timeout = kw.get('timeout', 3600)
        # Form variable for username
        self.namevar = kw.get('namevar', 'username')       

    def __call__(self, environ, start_response):
        if not self.authenticate(environ):
            result = self.authorize(environ)
            # Request credentials if no authority
            if hasattr(result, '__call__'):
                return result(environ, start_response)
            # Set environ
            environ['REMOTE_USER'] = result
            environ['AUTH_TYPE'] = self.authtype
            environ['REQUEST_METHOD'] = 'GET'
            environ['CONTENT_LENGTH'] = ''
            environ['CONTENT_TYPE'] = ''
            # Send initial response
            return self.initial(environ, start_response)            
        return self.application(environ, start_response)        
        
    def authorize(self, environ):
        '''Checks authorization credentials for a request.'''
        # Provide persistence for already authenticated requests
        if environ.get('REMOTE_USER') is not None:
            return environ.get('REMOTE_USER')
        # Complete authorization process
        elif environ['REQUEST_METHOD'] == 'POST':
            # Get user credentials
            userdata = extract(environ)
            # Check authorization of user credentials
            if self.authfunc(userdata):               
                return userdata[self.namevar]
            return self.response
        return self.response

    def _authtoken(self, environ, token):
        '''Authenticates authentication tokens.'''
        authtoken = base64.urlsafe_b64decode(token)
        # Get authentication token
        current = authtoken[:_cryptsize]
        # Get expiration time
        date = gettime(authtoken[_cryptsize:].decode('hex'))
        # Check if authentication is expired
        if date > datetime.now().replace(microsecond=0):
            # Get onetime token info
            once = self.tracker[token]
            user, path, nonce = once['user'], once['path'], once['nonce'] 
            # Perform full token authentication if authlevel != 4
            if self.authlevel != 4:
                agent = environ['HTTP_USER_AGENT']                
                raddr = environ['REMOTE_ADDR']
                server = environ['SERVER_NAME']
                newtoken = self.compute(user, raddr, server, path, agent, nonce)
                if newtoken != current: return False
            # Set user and authentication type
            environ['REMOTE_USER'] = user
            environ['AUTH_TYPE'] = self.authtype
            return True

    def compute(self, user, raddr, server, path, agent, nonce):
        '''Computes a token.'''
       
        # Verify minimum path and user auth
        if self.authlevel == 3 or 4:
            key = self._secret.join([path, nonce, user])
        # Verify through 3 + agent and originating server
        elif self.authlevel == 2:
            key = self._secret.join([user, path, nonce, server, agent])
        # Verify through 2 + IP address
        elif self.authlevel == 1:
            key = self._secret.join([raddr, user, server, nonce, agent, path])
        # Return HMAC signed token
        return hmac.new(self._secret, key, sha).hexdigest()        

    def _gettoken(self, environ):
        '''Generates authentication tokens.'''
        user, path = environ['REMOTE_USER'], getpath(environ)
        agent = environ['HTTP_USER_AGENT']
        raddr, server = environ['REMOTE_ADDR'], environ['SERVER_NAME']
        # Onetime secret
        nonce = getsecret()
        # Compute authentication token
        authtoken = self.compute(user, raddr, server, path, agent, nonce)
        # Compute token timeout
        timeout = datetime.fromtimestamp(time.time() + self.timeout).ctime()
        # Generate persistent token
        token = base64.urlsafe_b64encode(authtoken + timeout.encode('hex'))
        # Store onetime token info for future authentication
        self.tracker[token] =  {'user':user, 'path':path, 'nonce':nonce}
        return token

    def authenticate(self, environ):
        '''"Interface" for subclasses.'''
        raise NotImplementedError()

    def generate(self, environ):
        '''"Interface" for subclasses.'''
        raise NotImplementedError()

    def initial(self, environ, start_response):
        '''"Interface" for subclasses.'''
        raise NotImplementedError()


class Scheme(object):

    '''HTTP Authentication Base.'''    

    _msg = 'This server could not verify that you are authorized to\r\n' \
    'access the document you requested.  Either you supplied the\r\n' \
    'wrong credentials (e.g., bad password), or your browser\r\n' \
    'does not understand how to supply the credentials required.' 
    
    def __init__(self, realm, authfunc, **kw):
        self.realm, self.authfunc = realm, authfunc
        # WSGI app that sends a 401 response
        self.response = kw.get('response', self._response)
        # Message to return with 401 response
        self.message = kw.get('message', self._msg)    
    

class HTTPAuth(object):

    '''HTTP authentication middleware.'''    
    
    def __init__(self, application, realm, authfunc, scheme, **kw):
        '''
        @param application WSGI application.
        @param realm Identifier for authority requesting authorization.
        @param authfunc Mandatory user-defined function
        @param scheme HTTP authentication scheme            
        '''
        self.application = application
        self.authenticate = scheme(realm, authfunc, **kw)
        self.scheme = scheme.authtype

    def __call__(self, environ, start_response):
        if environ.get('REMOTE_USER') is None:
            result = self.authenticate(environ)
            if not isinstance(result, str):
                return result(environ, start_response)
            environ['REMOTE_USER'] = result
            environ['AUTH_TYPE'] = self.scheme    
        return self.application(environ, start_response)    