# (c) 2005 Ian Bicking and contributors; written for Paste (http://pythonpaste.org)
# Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php

'''Authenticate based on IP address.'''

def authfunc(environ, ipaddr):
    '''An example IP authentication function. 'environ'
    contains a REMOTE_USER header that has been set by some
    other authentication method and that name is matched against the
    IP address that user should be using.

    @param environ Environment dict
    @param ipaddr Remote IP address
    '''
    return environ['REMOTE_USER'] == ip_user_map[ipaddr]


class IPAuth(object):

    '''On each request, `REMOTE_ADDR` is authenticated and access is allowed
    based on that.
    '''

    def __init__(self, app, authfunc, **kw):
        self.app, self.authfunc = app, authfunc 
        self.handler = kw.get('handler', self.authresponse)

    def authresponse(self, environ, start_response):
        start_response('403 Forbidden', [('content-type', 'text/plain')])
        return ['This server could not verify that you are authorized to\r\n'
            'access the resource you requested from your current location.\r\n']                                     
        
    def __call__(self, environ, start_response):
        ipaddr = environ.get('REMOTE_ADDR')
        if not self.authfunc(environ, ipaddr):
            return self.handler(environ, start_response)            
        return self.app(environ, start_response)
        
                
def ipauth(authfunc, **kw):
    '''Decorator for IP address-based authentication.'''
    def decorator(application):
        return IPAuth(application, authfunc, **kw)
    return decorator

__all__ = ['IPAuth', 'ipauth']