import cgi
try:
    from wsgiref.util import request_uri
except ImportError:
    from util import request_uri
from util import Redir

__all__ = ['URLAuth', 'urlauth']

def urlauth(authfunc, **kw):
    '''Decorator for url authentication.'''
    def decorator(application):
        return URLAuth(application, authfunc, **kw)
    return decorator


class URLAuth(_AuthBase):

    authtype = 'url'

    def __call__(self, environ, start_response):
        auth = self.authenticate(environ)
        if not auth:
            authority = self.authorize(environ)
            if not authority: return self.response(environ, start_response)
            redirect = Redir(self.generate(environ))
            return redirect(environ, start_response)
        return self.application(environ, start_response)     

    def _validate(self, environ):
        try:
            query = cgi.parse_qs(environ['QUERY_STRING'])        
            return self._authid(environ, query[self.name][0])
        except KeyError:
            return False
        
    def _generate(self, environ):
        authstring = self._getid(environ)
        aqstring = '%s=%s' % (self.name, authstring)
        environ['QUERY_STRING'] = aqstring
        return request_uri(environ)