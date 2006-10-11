import cgi

def extract(environ, empty=False, err=False):
    '''Extracts strings in form data.'''
    qdict = cgi.parse(environ['wsgi.input'], environ, empty, err)
    for key, value in qdict.iteritems():
        if len(value) == 1: qdict[key] = value[0]
    return qdict