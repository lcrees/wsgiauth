# (c) 2005 Clark C. Evans
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com

'''CAS 1.0 Authentication

The Central Authentication System is a straight-forward single sign-on
mechanism developed by Yale University's ITS department.  It has since
enjoyed widespread success and is deployed at many major universities
and some corporations.

    https://clearinghouse.ja-sig.org/wiki/display/CAS/Home
    http://www.yale.edu/tp/auth/usingcasatyale.html

This implementation has the goal of maintaining current path arguments
passed to the system so that it can be used as middleware at any stage
of processing.  It has the secondary goal of allowing for other
authentication methods to be used concurrently.
'''

import urllib
from wsgiref.util import request_uri


class _Redir(object):

    def __init__(self, location):
        self.location = location

    def __call__(self, environ, start_response):
        start_response('303 Forbidden', [('content-type', 'text/plain'),
                ('location', self.location)])
        return ['You are being redirected to %s so you can be' \
                'authenticated.\r\n' % self.location]   


class CAS(object):

    '''Middleware to implement CAS 1.0 authentication

    There are several possible outcomes:

    0. If the REMOTE_USER environment variable is already populated;
       then this middleware is a no-op, and the request is passed along
       to the application.

    1. If a query argument 'ticket' is found, then an attempt to
       validate said ticket /w the authentication service done.  If the
       ticket is not validated; an 403 'Forbidden' exception is raised.
       Otherwise, the REMOTE_USER variable is set with the NetID that
       was validated and AUTH_TYPE is set to "cas".

    2. Otherwise, a 303 'See Other' is returned to the client directing
       them to login using the CAS service.  After logon, the service
       will send them back to this same URL, only with a 'ticket' query
       argument.

    Parameters:

        ``authority``

            This is a fully-qualified URL to a CAS 1.0 service. The URL
            should end with a '/' and have the 'login' and 'validate'
            sub-paths as described in the CAS 1.0 documentation.
    '''

    def __init__(self, application, authority, **kw):
        assert authority.endswith('/') and authority.startswith('http')
        self.authority = authority
        self.application = application
        self.redirect = kw.get('redirect', _Redir)
        self.forbidden = kw.get('forbidden', self._verboten)    
    
    def __call__(self, environ, start_response):        
        username = environ.get('REMOTE_USER')
        if username is not None: return self.application(environ, start_response)
        qs = environ.get('QUERY_STRING', '').split('&')
        if qs and qs[-1].startswith('ticket='):
            # assume a response from the authority
            ticket = qs.pop().split('=', 1)[1]
            environ['QUERY_STRING'] = '&'.join(qs)
            service = request_uri(environ)
            args = urllib.urlencode({'service':service, 'ticket':ticket})
            requrl = ''.join([self.authority, 'validate?', args])
            result = urllib.urlopen(requrl).read().split('\n')
            if 'yes' == result[0]:
                environ['REMOTE_USER'] = result[1]
                environ['AUTH_TYPE'] = 'cas'
                return self.application(environ, start_response)
            exce = self.forbidden
        else:
            service = request_uri(environ)
            args = urllib.urlencode({'service':service})
            location = ''.join([self.authority, 'login?', args])
            exce = self.redirect(location)
        return exce(environ, start_response)

    def _verboten(self, environ, start_response):
        start_response('403 Forbidden', [('content-type', 'text/plain')])
        return ['This server could not verify that you are authorized to\r\n'
            'access the resource you requested from your current location.\r\n']



def cas(authority, **kw):
    '''Decorator for CAS authentication.'''
    def decorator(application):
        return CAS(application, authority, **kw)
    return decorator

__all__ = ['CAS', 'cas']