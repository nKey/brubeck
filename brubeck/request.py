import json
import Cookie
import logging
import urlparse
import re

try:
    from collections import OrderedDict
except:
    from ordereddict import OrderedDict

logger = logging.getLogger(__name__)


def parse_netstring(ns):
    length, rest = ns.split(':', 1)
    length = int(length)
    assert rest[length] == ',', "Netstring did not end in ','"
    return rest[:length], rest[length + 1:]


def to_bytes(data, enc='utf8'):
    """Convert anything to bytes
    """
    return data.encode(enc) if isinstance(data, unicode) else bytes(data)


def to_unicode(s, enc='utf8'):
    """Convert anything to unicode
    """
    return s if isinstance(s, unicode) else unicode(str(s), encoding=enc)


def uncgi(headers):
    """Cleaned up WSGI headers
    """
    new_headers = Headers()
    for key, value in headers.iteritems():
        if key.upper().startswith('HTTP_'):
            new_headers[key[5:].replace('_', '-')] = value
        elif '_' in key:
            new_headers[key.replace('_', '-')] = value
    return new_headers


class Request(object):
    """Word.
    """
    def __init__(self, sender, conn_id, path, headers, body, url, *args, **kwargs):
        self.sender = sender
        self.path = path
        self.conn_id = conn_id
        self.headers = headers
        self.body = body
        self.url_parts = urlparse.urlsplit(url) if isinstance(url, basestring) else url

        if self.method == 'JSON':
            self.data = json.loads(body)
        else:
            self.data = {}

        ### populate arguments with QUERY string
        self.arguments = {}
        if 'QUERY' in self.headers:
            query = self.headers['QUERY']
            arguments = urlparse.parse_qs(query.encode("utf-8"))
            for name, values in arguments.iteritems():
                values = [v for v in values if v]
                if values:
                    self.arguments[name] = values

        ### handle data, multipart or not
        if self.method in ("POST", "PUT") and self.content_type:
            form_encoding = "application/x-www-form-urlencoded"
            if self.content_type.startswith(form_encoding):
                arguments = urlparse.parse_qs(self.body, keep_blank_values=True)
                self.arguments.update(arguments)
            # Not ready for this, but soon
            elif self.content_type.startswith("multipart/form-data"):
                fields = self.content_type.split(";")
                for field in fields:
                    k, sep, v = field.strip().partition("=")
                    if k == "boundary" and v:
                        self.arguments = {}
                        self.files = {}
                        self._parse_mime_body(v, self.body, self.arguments,
                                              self.files)
                        break
                else:
                    logger.warning("Invalid multipart/form-data")

    def _parse_mime_body(self, boundary, data, arguments, files):
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]
        if data.endswith("\r\n"):
            footer_length = len(boundary) + 6
        else:
            footer_length = len(boundary) + 4
        data = str(data)
        parts = data[:-footer_length].split("--" + str(boundary) + "\r\n")
        for part in parts:
            if not part:
                continue
            eoh = part.find("\r\n\r\n")
            if eoh == -1:
                logger.warning("multipart/form-data missing headers")
                continue
            #headers = HTTPHeaders.parse(part[:eoh].decode("utf-8"))
            header_string = part[:eoh].decode("utf-8")
            headers = Headers()
            last_key = ''
            for line in header_string.splitlines():
                if line[0].isspace():
                    # continuation of a multi-line header
                    new_part = ' ' + line.lstrip()
                    headers[last_key] += new_part
                else:
                    name, value = line.split(":", 1)
                    last_key = "-".join([w.capitalize() for w in name.split("-")])
                    headers[name] = value.strip()

            disp_header = headers.get("Content-Disposition", "")
            disposition, disp_params = self._parse_header(disp_header)
            if disposition != "form-data" or not part.endswith("\r\n"):
                logger.warning("Invalid multipart/form-data")
                continue
            value = part[eoh + 4:-2]
            if not disp_params.get("name"):
                logger.warning("multipart/form-data value missing name")
                continue
            name = disp_params["name"]
            if disp_params.get("filename"):
                ctype = headers.get("Content-Type", "application/unknown")
                files.setdefault(name, []).append(dict(
                    filename=disp_params["filename"], body=value,
                    content_type=ctype))
            else:
                arguments.setdefault(name, []).append(value)

    def _parseparam(self, s):
        while s[:1] == ';':
            s = s[1:]
            end = s.find(';')
            while end > 0 and (s.count('"', 0, end) - s.count('\\"', 0, end)) % 2:
                end = s.find(';', end + 1)
            if end < 0:
                end = len(s)
            f = s[:end]
            yield f.strip()
            s = s[end:]

    def _parse_header(self, line):
        """Parse a Content-type like header.

        Return the main content-type and a dictionary of options.
        """
        parts = self._parseparam(';' + line)
        key = parts.next()
        pdict = {}
        for p in parts:
            i = p.find('=')
            if i >= 0:
                name = p[:i].strip().lower()
                value = p[i + 1:].strip()
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1]
                    value = value.replace('\\\\', '\\').replace('\\"', '"')
                pdict[name] = value
        return key, pdict

    @property
    def method(self):
        return self.headers.get('METHOD')

    @property
    def content_type(self):
        return self.headers.get("content-type")

    @property
    def version(self):
        return self.headers.get('VERSION')

    @property
    def remote_addr(self):
        return self.headers.get('x-forwarded-for')

    @property
    def cookies(self):
        """Lazy generation of cookies from request headers."""
        if not hasattr(self, "_cookies"):
            self._cookies = Cookie.SimpleCookie()
            if "cookie" in self.headers:
                try:
                    cookies = self.headers['cookie']
                    self._cookies.load(to_bytes(cookies))
                except Exception:
                    logger.error('Failed to load cookies')
                    self.clear_all_cookies()
        return self._cookies

    @property
    def url(self):
        return self.url_parts.geturl()

    @property
    def host(self):
        return urlparse.urlunsplit(
            (self.url_parts.scheme, self.url_parts.netloc, '', '', ''))

    @staticmethod
    def parse_msg(msg):
        """Static method for constructing a Request instance out of a
        message read straight off a zmq socket.
        """
        sender, conn_id, path, rest = msg.split(' ', 3)
        headers, rest = parse_netstring(rest)
        body, _ = parse_netstring(rest)
        headers = Headers(json.loads(headers))
        # construct url from request
        scheme = headers.get('URL_SCHEME', 'http')
        netloc = headers.get('host')
        path = headers.get('PATH')
        query = headers.get('QUERY')
        url = urlparse.SplitResult(scheme, netloc, path, query, None)
        r = Request(sender, conn_id, path, headers, body, url)
        r.is_wsgi = False
        return r

    @staticmethod
    def parse_wsgi_request(environ):
        """Static method for constructing Request instance out of environ
        dict from wsgi server."""
        conn_id = None
        sender = "WSGI_server"
        path = environ['PATH_INFO']
        body = ""
        if "CONTENT_LENGTH" in environ and environ["CONTENT_LENGTH"]:
            body = environ["wsgi.input"].read(int(environ['CONTENT_LENGTH']))
            del environ["wsgi.input"]
        # normalize environ dict
        headers = Headers(environ)
        headers.update(uncgi(environ))
        if 'REQUEST_METHOD' in headers:
            headers['METHOD'] = headers['REQUEST_METHOD']
        if 'QUERY_STRING' in headers:
            headers['QUERY'] = headers['QUERY_STRING']
        headers['VERSION'] = headers.get('SERVER_PROTOCOL', 'HTTP/1.1')
        # construct url from request
        scheme = headers['wsgi.url_scheme']
        netloc = headers.get('HTTP_HOST')
        if not netloc:
            netloc = headers['SERVER_NAME']
            port = headers['SERVER_PORT']
            if ((scheme == 'https' and port != '443') or
                (scheme == 'http' and port != '80')):
                netloc += ':' + port
        path = headers.get('SCRIPT_NAME', '')
        path += headers.get('PATH_INFO', '')
        query = headers.get('QUERY_STRING', None)
        url = urlparse.SplitResult(scheme, netloc, path, query, None)
        r = Request(sender, conn_id, path, headers, body, url)
        r.is_wsgi = True
        return r

    def is_disconnect(self):
        if self.headers.get('METHOD') == 'JSON':
            logger.error('DISCONNECT')
            return self.data.get('type') == 'disconnect'

    def should_close(self):
        """Determines if Request data matches criteria for closing request"""
        if self.headers.get('connection') == 'close':
            return True
        elif self.headers.get('VERSION') == 'HTTP/1.0':
            return True
        else:
            return False

    def get_arguments(self, name, strip=True):
        """Returns a list of the arguments with the given name. If the argument
        is not present, returns a None. The returned values are always unicode.
        """
        values = self.arguments.get(name, None)
        if values is None:
            return None

        # Get the stripper ready
        if strip:
            stripper = lambda v: v.strip()
        else:
            stripper = lambda v: v

        def clean_value(v):
            v = re.sub(r"[\x00-\x08\x0e-\x1f]", " ", v)
            v = to_unicode(v)
            v = stripper(v)
            return v

        values = [clean_value(v) for v in values]
        return values

    def get_argument(self, name, default=None, strip=True):
        """Returns the value of the argument with the given name.

        If the argument appears in the url more than once, we return the
        last value.
        """
        args = self.get_arguments(name, strip=strip)
        if not args:
            return default
        return args[-1]


class Headers(OrderedDict):
    """Ordered dictionary with case insensitive lookup that preserves original
    case when listing.
    """

    class CaseInsensitiveString(str):
        def __hash__(self):
            """
            >>> hash(Headers.CaseInsensitiveString('Doc')) == hash('doc')
            True
            """
            return hash(self.lower())

        def __eq__(self, other):
            """
            >>> Headers.CaseInsensitiveString('Doc') == 'doc'
            True
            """
            return self.lower() == other.lower()

    def __keytransform__(self, key):
        return self.CaseInsensitiveString(key)

    def __contains__(self, key):
        """
        >>> 'USER-AGENT' in Headers({'User-Agent': 'doctest'})
        True
        """
        return super(Headers, self).__contains__(self.__keytransform__(key))

    def __getitem__(self, key):
        """
        >>> h = Headers({'User-Agent': 'doctest'})
        >>> h['USER-AGENT']
        'doctest'
        """
        return super(Headers, self).__getitem__(self.__keytransform__(key))

    def __setitem__(self, key, value):
        """
        >>> h = Headers()
        >>> h['User-Agent'] = 'doctest'
        >>> h['USER-AGENT']
        'doctest'
        """
        return super(Headers, self).__setitem__(self.__keytransform__(key), value)

    def __delitem__(self, key):
        """
        >>> h = Headers({'User-Agent': 'doctest'})
        >>> del h['USER-AGENT']
        >>> 'User-Agent' not in h
        True
        """
        return super(Headers, self).__delitem__(self.__keytransform__(key))

    def has_key(self, key):
        """
        >>> Headers({'User-Agent': 'doctest'}).has_key('USER-AGENT')
        True
        """
        return super(Headers, self).has_key(self.__keytransform__(key))

    def get(self, key, *args):
        """
        >>> Headers({'User-Agent': 'doctest'}).get('USER-AGENT')
        'doctest'
        >>> Headers().get('User-Agent', 'doctest')
        'doctest'
        """
        return super(Headers, self).get(self.__keytransform__(key), *args)
