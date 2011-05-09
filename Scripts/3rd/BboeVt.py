"""
Original code by Bryce Boe: http://www.bryceboe.com/2010/09/01/submitting-binaries-to-virustotal/

Modified by Elias Bachaalany <elias at hex-rays.com>

"""

import hashlib, httplib, mimetypes, os, pprint, simplejson, sys, urlparse

# -----------------------------------------------------------------------
DEFAULT_TYPE = 'application/octet-stream'
FILE_REPORT_URL = 'https://www.virustotal.com/api/get_file_report.json'
SCAN_URL = 'https://www.virustotal.com/api/scan_file.json'
API_KEY = "" # Put API key here. Register an account in VT Community


# -----------------------------------------------------------------------
# The following function is modified from the snippet at:
# http://code.activestate.com/recipes/146306/
def _encode_multipart_formdata(fields, files=()):
    """
    fields is a dictionary of name to value for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files.
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for key, value in fields.items():
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' %
                 (key, filename))
        content_type = mimetypes.guess_type(filename)[0] or DEFAULT_TYPE
        L.append('Content-Type: %s' % content_type)
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


# -----------------------------------------------------------------------
def _post_multipart(url, fields, files=()):
    """
    url is the full to send the post request to.
    fields is a dictionary of name to value for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files.
    Return body of http response.
    """
    content_type, data = _encode_multipart_formdata(fields, files)
    url_parts = urlparse.urlparse(url)
    if url_parts.scheme == 'http':
        h = httplib.HTTPConnection(url_parts.netloc)
    elif url_parts.scheme == 'https':
        h = httplib.HTTPSConnection(url_parts.netloc)
    else:
        raise Exception('Unsupported URL scheme')
    path = urlparse.urlunparse(('', '') + url_parts[2:])
    h.request('POST', path, data, {'content-type':content_type})
    return h.getresponse().read()


# -----------------------------------------------------------------------
def set_apikey(key, dbg = False):
    """
    Set the VT API key
    """
    global API_KEY
    API_KEY = key
    if dbg:
        httplib.HTTPConnection.debuglevel = 1



# -----------------------------------------------------------------------
def scan_file(filename):
    """
    Uploads a file for scanning.

    @param filename: The filename to upload

    @return: - None if upload failed
             - scan_id value if upload succeeds
             - raises an exception on IO failures
    """
    files = [('file', filename, open(filename, 'rb').read())]
    json = _post_multipart(SCAN_URL, {'key':API_KEY}, files)
    data = simplejson.loads(json)
    return str(data['scan_id']) if data['result'] == 1 else None


# -----------------------------------------------------------------------
def get_file_md5_hash(filename):
    f = open(filename, 'rb')
    r = hashlib.md5(f.read()).hexdigest()
    f.close()
    return r


# -----------------------------------------------------------------------
def get_file_report(filename=None, md5sum=None):
    """
    Returns an report for a file or md5su.

    @param filename: File name to get report. The file is used just
                     to compute its MD5Sum
    @param md5sum: MD5sum string (in case filename was not passed)

    @return: - None: if file was not previously analyzed
             - A dictionary if report exists: key=scanner, value=reported name
    """
    if filename is None and md5sum is None:
        raise Exception('Either filename or md5sum should be passed!')

    # Filename passed? Compute its MD5
    if filename:
        global LAST_FILE_HASH
        LAST_FILE_HASH = md5sum = get_file_md5_hash(filename)

    # Form the request
    json = _post_multipart(FILE_REPORT_URL, {'resource':md5sum, 'key':API_KEY})
    data = simplejson.loads(json)
    if data['result'] != 1:
        # No results
        return None
    else:
        # date, result_dict = data['report']
        return data['report'][1]


# -----------------------------------------------------------------------
def pretty_print(obj):
    pprint.pprint(obj)


# -----------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: %s filename' % sys.argv[0])
        sys.exit(1)

    filename = sys.argv[1]
    if not os.path.isfile(filename):
        print('%s is not a valid file' % filename)
        sys.exit(1)

    get_file_report(filename=filename)