# (c) 2005 Ian Bicking and contributors; written for Paste (http://pythonpaste.org)
# Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php

'''Authenticate based on IP address.'''


class IP(object):

    '''On each request, `REMOTE_ADDR` is authenticated and access is allowed
    based on that.
    '''

    def __init__(self, app, authfunc, **kw):
        self.app, self.authfunc = app, authfunc 
        self.authresponse = kw.get('handler', IP._authresponse)

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
        
                
def ip(authfunc, **kw):
    '''Decorator for IP address-based authentication.'''
    def decorator(application):
        return IP(application, authfunc, **kw)
    return decorator

__all__ = ['IP', 'ip']