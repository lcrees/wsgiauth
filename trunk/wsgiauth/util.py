import cgi
from urllib import quote


class Redir(object):

    def __init__(self, location):
        self.location = location

    def __call__(self, environ, start_response):
        start_response('302 Found', [('content-type', 'text/html'),
            ('location', self.location)])
        return ['<html>\n<head><title>Redirecting to %s</title><head>\n' \
        '<body>You are being redirected to <a href="%s">%s</a>' \
        '</body></html>\n' % (self.location, self.location, self.location)]


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
    '''Rebuilds request URI (from PEP 333).
    
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
    url += quote(environ.get('SCRIPT_NAME',''))
    url += quote(environ.get('PATH_INFO',''))
    if include_query and environ.get('QUERY_STRING'):
        url += '?' + environ['QUERY_STRING']
    return url    