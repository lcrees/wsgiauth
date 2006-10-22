import cgi
from urllib import quote


class Redir(object):

    '''WSGI application for HTTP 30x redirects.'''    

    def __init__(self, location, **kw):
        self.location = location
        self.status = kw.get('status', '302 Found')
        self.message = kw.get('message', Redir._message) 

    def __call__(self, environ, start_response):
        start_response(self.status, [('content-type', 'text/html'),
            ('location', self.location)])
        return self.message(self.location)
        
    @classmethod
    def _message(cls, location):
        '''HTTP 30x message body.'''
        return ['<html>\n<head><title>Redirecting to %s</title></head>\n' \
        '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
        '</body>\n</html>' % (location, location, location)]


class Forbidden(object):
    
    '''WSGI application informing a user agent that it lacks credentials for a
    website location.'''

    def __init__(self, **kw):
        self.location = kw.get('location')
        self.message = kw.get('message', Forbidden._message)
        
    def __call__(self, environ, start_response):
        start_response('403 Forbidden', [('content-type', 'text/plain')])
        return self.message(self.location)

    @classmethod    
    def _message(cls, location):
        '''A message that a path is forbidden.'''
        if location is None:
            return ['This server could not verify that you are authorized to' \
             'access the resource you requested from your current location.']
        return ['This server could not verify that you are authorized to' \
             'access %s from your current location.' % location]


def extract(environ, empty=False, err=False):
    '''Extracts strings in form data and returns a dict.

    @param environ WSGI environ
    @param empty Stops on empty fields (default: Fault)
    @param err Stops on errors in fields (default: Fault)
    '''
    formdata = cgi.parse(environ['wsgi.input'], environ, empty, err)    
    # Remove single entries from lists
    for key, value in formdata.iteritems():
        if len(value) == 1: formdata[key] = value[0]   
    return formdata

def request_uri(environ, include_query=1):
    '''Algorithm for rebuilding request URI (from PEP 333).
    
    @param environ WSGI environ
    @include_query Is QUERY_STRING included in URI (default: 1)
    '''    
    url = environ['wsgi.url_scheme'] + '://'
    if environ.get('HTTP_HOST'):
        url += environ['HTTP_HOST']
    else:
        url += environ['SERVER_NAME']
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                url += ':' + environ['SERVER_PORT']
        else:
            if environ['SERVER_PORT'] != '80':
                url += ':' + environ['SERVER_PORT']
    url += quote(environ.get('SCRIPT_NAME', ''))
    url += quote(environ.get('PATH_INFO', ''))
    if include_query and environ.get('QUERY_STRING'):
        url += '?' + environ['QUERY_STRING']
    return url