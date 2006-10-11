# (c) 2005 Clark C. Evans
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com

'''Basic HTTP/1.0 Authentication

This module implements basic HTTP authentication as described in
HTTP/1.0 specification:

http://www.w3.org/Protocols/HTTP/1.0/draft-ietf-http-spec.html#BasicAA

Do not use this module unless you are using SSL or need to work with very
out-dated clients, instead use HTTP digest authentication. 
'''


class BasicAuth(object):

    '''Performs basic HTTP authentication.'''

    _rsp_msg = '''This server could not verify that you are authorized to\r\n
        access the document you requested.  Either you supplied the\r\n
        wrong credentials (e.g., bad password), or your browser\r\n
        does not understand how to supply the credentials required.\r\n'''    
    
    def __init__(self, realm, authfunc, **kw):
        self.realm, self.authfunc = realm, authfunc
        self.authresponse = kw.get('errhandler', self._authresponse)
        self.message = kw.get('message', self._rsp_msg)

    def _authresponse(self, environ, start_response):
        ''''''
        start_response('401 Unauthorized', [('content-type', 'text/plain'),
            ('WWW-Authenticate', 'Basic realm="%s"' % self.realm)])
        return [self.message]

    def __call__(self, environ):
        try:
            authorization = environ['HTTP_AUTHORIZATION']
            authmeth, auth = authorization.split(' ', 1)
            if 'basic' != authmeth.lower(): return self.authresponse
            auth = auth.strip().decode('base64')
            username, password = auth.split(':', 1)
            if self.authfunc(environ, username, password): return username
        except KeyError:
            return self.authresponse
        return self.authresponse


class Basic(object):

    '''HTTP basic authentication middleware.'''    
    
    def __init__(self, application, realm, authfunc):
        '''@param application The application object is called only upon
            successful authentication, and can assume environ['REMOTE_USER']
            is set. If REMOTE_USER is already set, this middleware is simply
            pass-through.

        @param realm This is a identifier for the authority that is requesting
            authorization. It is shown to the user and should be unique within
            the domain it is being used.

        @param authfunc This is a mandatory user-defined function which takes a
            environ, username and password for its first three arguments.  It
            should return True if the user is authenticated.
        '''
        self.application = application
        self.authenticate = BasicAuth(realm, authfunc)

    def __call__(self, env, start_response):
        '''WSGI callable.'''
        try:
            username = env['REMOTE_USER']
        except KeyError:
            result = self.authenticate(env)
            if not isinstance(result, str): return result(env, start_response)
            env['AUTH_TYPE'], env['REMOTE_USER'] = 'basic', result    
        return self.application(env, start_response)


def basic(realm, authfunc, **kw):
    '''Decorator for basic authentication.'''
    def decorator(application):
        return Basic(application, realm, authfunc, **kw)
    return decorator


__all__ = ['Basic', 'basic']