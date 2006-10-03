# (c) 2005 Clark C. Evans
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com

"""
Basic HTTP/1.0 Authentication

This module implements ``Basic`` authentication as described in
HTTP/1.0 specification [1]_ .  Do not use this module unless you
are using SSL or need to work with very out-dated clients, instead
use ``digest`` authentication.

.. [1] http://www.w3.org/Protocols/HTTP/1.0/draft-ietf-http-spec.html#BasicAA
"""


class AuthBasicAuthenticator:
    """
    implements ``Basic`` authentication details
    """

    def __init__(self, realm, authfunc, use401=True, errhandler=None):
        self.realm = realm
        self.authfunc = authfunc
        self.use401 = use401
        self.errorhandler = errhandler

    def build_authentication(self, environ, start_response):
        start_response('401 Unauthorized', [("content-type","text/plain"),
            ("WWW-Authenticate", 'Basic realm="%s"' % self.realm)])
        if self.use401:
            return ['This server could not verify that you are authorized to\r\n'
            'access the document you requested.  Either you supplied the\r\n'
            'wrong credentials (e.g., bad password), or your browser\r\n'
            'does not understand how to supply the credentials required.\r\n']
        else:
             return self.errorhandler(environ, start_response)

    def __call__(self, environ):
        authorization = environ.get('HTTP_AUTHORIZATION')
        if authorization is None: return self.build_authentication
        authmeth, auth = authorization.split(' ', 1)
        if 'basic' != authmeth.lower(): return self.build_authentication
        auth = auth.strip().decode('base64')
        username, password = auth.split(':', 1)
        if self.authfunc(environ, username, password): return username
        return self.build_authentication

class AuthBasicHandler:
    """
    HTTP/1.0 ``Basic`` authentication middleware

    Parameters:

        ``application``

            The application object is called only upon successful
            authentication, and can assume ``environ['REMOTE_USER']``
            is set.  If the ``REMOTE_USER`` is already set, this
            middleware is simply pass-through.

        ``realm``

            This is a identifier for the authority that is requesting
            authorization.  It is shown to the user and should be unique
            within the domain it is being used.

        ``authfunc``

            This is a mandatory user-defined function which takes a
            ``environ``, ``username`` and ``password`` for its first
            three arguments.  It should return ``True`` if the user is
            authenticated.

    """
    def __init__(self, application, realm, authfunc):
        self.application = application
        self.authenticate = AuthBasicAuthenticator(realm, authfunc)

    def __call__(self, environ, start_response):
        username = environ.get('REMOTE_USER', None)
        if username is None:
            result = self.authenticate(environ)
            if isinstance(result, str):
                environ['AUTH_TYPE'] = 'basic'
                environ['REMOTE_USER'] = result
            else:
                return result(environ, start_response)
        return self.application(environ, start_response)


def basic(realm, authfunc):
    '''Decorator for simple cache.'''
    def decorator(application):
        return AuthBasicHandler(application, realm, authfunc)
    return decorator


__all__ = ['AuthBasicHandler']