from urllib import quote

def application_uri(environ):
    '''Return the application's base URI (no PATH_INFO or QUERY_STRING)'''
    url = ''.join([environ['wsgi.url_scheme'], '://'])    
    if environ.get('HTTP_HOST'):
        url = ''.join([url, environ['HTTP_HOST']])
    else:
        url, port = ''.join([url, environ['SERVER_NAME']]), environ['SERVER_PORT']
        if environ['wsgi.url_scheme'] == 'https':
            if port != '443': url = ':'.join([url, port])
        else:
            if port != '80': url = ':'.join([url, port])
    url = ''.join([url, quote(environ.get('SCRIPT_NAME') or '/')])
    return url

def request_uri(environ, include_query=True):
    '''Return the full request URI, optionally including the query string'''
    url = application_uri(environ)
    path_info = quote(environ.get('PATH_INFO',''))
    if not 'SCRIPT_NAME' in environ:
        url = ''.join([url, path_info[1:]])
    else:
        url = ''.join([url, path_info])
    if include_query and 'QUERY_STRING' in environ:
        url = '?'.join([url, environ['QUERY_STRING']])
    return url