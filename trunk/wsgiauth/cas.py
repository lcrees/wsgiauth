# (c) 2005 Clark C. Evans
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com

'''CAS 1.0 Authentication'''

import urllib
from util import Redirect, Forbidden, geturl

__all__ = ['CAS', 'cas']

def cas(authority, **kw):
    '''Decorator for CAS authentication.'''
    def decorator(application):
        return CAS(application, authority, **kw)
    return decorator


class CAS(object):

    '''Middleware for CAS 1.0 authentication.'''

    def __init__(self, application, authority, **kw):
        assert authority.endswith('/') and authority.startswith('http')
        # Fully-qualified URL to a CAS 1.0 service
        self.authority = authority
        self.application = application
        self.redirect = kw.get('redirect', Redirect)
        self.forbidden = kw.get('forbidden', Forbidden)
    
    def __call__(self, environ, start_response):        
        if environ.get('REMOTE_USER') is None:            
            qs = environ.get('QUERY_STRING', '').split('&')
            if qs and qs[-1].startswith('ticket='):
                # assume a response from the authority
                ticket = qs.pop().split('=', 1)[1]
                environ['QUERY_STRING'] = '&'.join(qs)
                service = geturl(environ)
                args = urllib.urlencode({'service':service, 'ticket':ticket})
                requrl = ''.join([self.authority, 'validate?', args])
                result = urllib.urlopen(requrl).read().split('\n')
                if 'yes' == result[0]:
                    environ['REMOTE_USER'] = result[1]
                    environ['AUTH_TYPE'] = 'cas'
                    return self.application(environ, start_response)
                exce = self.forbidden
            else:
                service = geturl(environ)
                args = urllib.urlencode({'service':service})
                location = ''.join([self.authority, 'login?', args])
                exce = self.redirect(location)
            return exce(environ, start_response)
        return self.application(environ, start_response)