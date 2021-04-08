#!/usr/bin/env python3

import werkzeug.local
import flask.wrappers


def addHeaders(resp: flask.wrappers.Response) -> flask.wrappers.Response:
    """
    Adds the no cache headers to a response

    >>> from flask import Flask, make_response
    >>> app = Flask(__name__)
    >>> with app.app_context():
    ...     blank_resp = make_response("OK")

    >>> resp = addHeaders(blank_resp)
    >>> for h in resp.headers:
    ...     print(h)
    ('Content-Type', 'text/html; charset=utf-8')
    ('Content-Length', '2')
    ('X-Robots-Tag', 'noindex, nofollow, noimageindex')
    ('Cache-Control', 'public, max-age=0')
    ('Pragma', 'no-cache')
    ('Expires', '0')

    """

    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noimageindex"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["Cache-Control"] = "public, max-age=0"
    return resp


def client_ip(request: werkzeug.local.LocalProxy) -> str:
    """
    Gets the client IP address from a request

    >>> from werkzeug.test import EnvironBuilder
    >>> from werkzeug.wrappers import Request

    >>> builder = EnvironBuilder(method='POST')
    >>> env = builder.get_environ()
    >>> req = Request(env)

    >>> client_ip(req) is None
    True

    >>> builder = EnvironBuilder(method='POST',
    ...   environ_overrides={'REMOTE_ADDR': '127.0.0.2'})
    >>> env = builder.get_environ()
    >>> req1 = Request(env)

    >>> client_ip(req1)
    '127.0.0.2'

    >>> builder = EnvironBuilder(method='POST',
    ...   environ_overrides={'HTTP_X_FORWARDED_FOR': '127.0.0.3, 127.0.0.2'})
    >>> env = builder.get_environ()
    >>> req2 = Request(env)

    >>> client_ip(req2)
    '127.0.0.3'

    >>> builder = EnvironBuilder(method='POST',
    ...   environ_overrides={'HTTP_X_FORWARDED_FOR': '::0, 127.0.0.2'})
    >>> env = builder.get_environ()
    >>> req3 = Request(env)

    >>> client_ip(req3)
    '::0'

    """

    ips = None

    if request.environ.get("HTTP_X_FORWARDED_FOR") is None:
        ips = request.environ.get("REMOTE_ADDR")
    else:
        ips = request.environ["HTTP_X_FORWARDED_FOR"]

    if ips:
        if "," in ips:
            return ips.split(",")[0].strip()
        else:
            return ips.strip()


if __name__ == "__main__":
    """
    If this python is called directly, test using doctest
    """
    import doctest

    doctest.testmod()
