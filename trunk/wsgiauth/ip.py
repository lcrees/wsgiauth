# (c) 2005 Ian Bicking and contributors; written for Paste
# (http://pythonpaste.org) # Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
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

'''Authenticate an IP address.'''

__all__ = ['IP', 'ip']

def ip(authfunc, **kw):
    '''Decorator for IP address-based authentication.'''
    def decorator(application):
        return IP(application, authfunc, **kw)
    return decorator


class IP(object):

    '''On each request, `REMOTE_ADDR` is authenticated and access is allowed
    based on that.
    '''

    def __init__(self, app, authfunc, **kw):
        self.app, self.authfunc = app, authfunc
        self.authresponse = kw.get('authresponse', IP._authresponse)

    def __call__(self, environ, start_response):
        ipaddr = environ.get('REMOTE_ADDR')
        if not self.authfunc(environ, ipaddr):
            return self.authresponse(environ, start_response)            
        return self.app(environ, start_response)

    @classmethod
    def _authresponse(cls, environ, start_response):
        start_response('403 Forbidden', [('content-type', 'text/plain')])
        return ['This server could not verify that you are authorized to\r\n'
         'access the resource you requested from your current location.\r\n']