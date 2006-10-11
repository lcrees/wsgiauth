# (c) 2005 Clark C. Evans
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com

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

import md5, sha, time, random, urllib2

def digest_password(realm, username, password):
    ''' construct the appropriate hashcode needed for HTTP digest '''
    return md5.md5('%s:%s:%s' % (username, realm, password)).hexdigest()

class _HTTPAuth(object):

    _rsp_msg = '''This server could not verify that you are authorized to\r\n
        access the document you requested.  Either you supplied the\r\n
        wrong credentials (e.g., bad password), or your browser\r\n
        does not understand how to supply the credentials required.\r\n''' 

    def __init__(self, realm, authfunc, **kw):
        self.realm, self.authfunc = realm, authfunc
        # WSGI app that sends a 401 response
        self.authresponse = kw.get('response', self._authresponse)
        # Message to return with 401 response
        self.message = kw.get('message', self._rsp_msg) 

class Basic(_HTTPAuth):

    '''Performs HTTP basic authentication.'''      
    
    def __init__(self, realm, authfunc, **kw):
        super(Basic, self).__init__(realm, authfunc, **kw)

    def _authresponse(self, environ, start_response):
        '''Default HTTP basic authentication response.'''
        start_response('401 Unauthorized', [('content-type', 'text/plain'),
            ('WWW-Authenticate', 'Basic realm="%s"' % self.realm)])
        return [self.message]

    def __call__(self, environ):
        '''This function takes a WSGI environment and authenticates
        the request returning authenticated user or error.
        '''
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


class Digest(_HTTPAuth):
    
    '''Performs HTTP digest authentication.'''
    
    def __init__(self, realm, authfunc, **kw):
        super(Digest, self).__init__(realm, authfunc, **kw)
        self.digest = kw.get('digest', md5)
        self.nonce = dict() # list to prevent replay attacks

    def authresponse(self, stale = ''):
        ''' builds the authentication error '''
        def coroutine(environ, start_response):
            nonce = self.digest.new('%s:%s' % (time.time(), random.random())).hexdigest()
            opaque = self.digest.new('%s:%s' % (time.time(), random.random())).hexdigest()
            self.nonce[nonce] = None
            parts = {'realm':self.realm, 'qop':'auth', 'nonce':nonce, 'opaque':opaque}
            if stale: parts['stale'] = 'true'
            head = ', '.join(['%s="%s"' % (k,v) for (k,v) in parts.items()])
            start_response('401 Unauthorized', [('content-type','text/plain'),
                ('WWW-Authenticate', 'Digest %s' % head)])
            return [self.message]
        return coroutine

    def compute(self, ha1, username, response, method,
                      path, nonce, nc, cnonce, qop):
        ''' computes the authentication, raises error if unsuccessful '''
        if not ha1: return self.authresponse()
        ha2 = self.digest.new('%s:%s' % (method, path)).hexdigest()
        if qop:
            chk = '%s:%s:%s:%s:%s:%s' % (ha1, nonce, nc, cnonce, qop, ha2)
        else:
            chk = '%s:%s:%s' % (ha1, nonce, ha2)
        if response != self.digest.new(chk).hexdigest():
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
        fullpath = ''.join([environ['SCRIPT_NAME'], environ['PATH_INFO']])
        authorization = environ.get('HTTP_AUTHORIZATION', None)
        if authorization is None: return self.authresponse()
        (authmeth, auth) = authorization.split(' ', 1)
        if 'digest' != authmeth.lower(): return self.authresponse()
        amap = {}
        for itm in auth.split(', '):
            (k, v) = [s.strip() for s in itm.split('=', 1)]
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
        return self.compute(ha1, username, response, method, authpath,
            nonce, nc, cnonce, qop)

    
class HTTPAuth(object):

    '''HTTP authentication middleware.

    This component follows the procedure below:

        1. If the REMOTE_USER environment variable is already populated;
           then this middleware is a no-op, and the request is passed
           along to the application.

        1. If the HTTP_AUTHORIZATION header was not provided, then a
           HTTPUnauthorized response is generated with the appropriate
           challenge.

        2. If the response is malformed or or if the user's credientials
           do not pass muster, another HTTPUnauthorized is raised.

        3. If all goes well, and the user's credintials pass; then
           REMOTE_USER environment variable is filled in and the
           AUTH_TYPE is listed as 'digest' or 'basic'.
    '''    
    
    def __init__(self, application, realm, authfunc, scheme):
        '''@param application The application object is called only upon
            successful authentication, and can assume environ['REMOTE_USER']
            is set. If REMOTE_USER is already set, this middleware is simply
            pass-through.

        @param realm This is a identifier for the authority that is requesting
            authorization. It is shown to the user and should be unique within
            the domain it is being used.

        @param authfunc For basic authentication, this is a mandatory user-defined
            function which takes a environ, username and password for its first
            three arguments. It should return True if the user is authenticated.

            For digest authentication, this is a callback function which performs
            the actual authentication; the signature of this callback is:

              authfunc(environ, realm, username) -> hashcode

            This module provides a 'digest_password' helper function which can help
            construct the hashcode; it is recommended that the hashcode is stored in
            a database, not the user's actual password (since you only need the
            hashcode).

        @param scheme Which HTTP authentication scheme to use, 'basic' or 'digest'            
        '''
        self.application, self.scheme = application, scheme
        if scheme == 'digest':
            self.authenticate = Digest(realm, authfunc)
        elif scheme == 'basic':
            self.authenticate = Basic(realm, authfunc)

    def __call__(self, env, start_response):
        '''WSGI callable.'''
        try:
            username = env['REMOTE_USER']
        except KeyError:
            result = self.authenticate(env)
            if not isinstance(result, str): return result(env, start_response)
            env['AUTH_TYPE'], env['REMOTE_USER'] = self.scheme, result    
        return self.application(env, start_response)


def basic(realm, authfunc):
    '''Decorator for basic authentication.'''
    def decorator(application):
        return HTTPAuth(application, realm, authfunc, 'basic')
    return decorator

def digest(realm, authfunc):
    '''Decorator for HTTP digest middleware.'''
    def decorator(application):
        return HTTPAuth(application, realm, authfunc, 'digest')
    return decorator

__all__ = ['HTTPAuth', 'basic', 'digest', 'digest_password']