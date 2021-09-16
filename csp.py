#!/usr/bin/env python3

import time
import json
import werkzeug.local
import re
import base64
from urllib.parse import urlparse
from utils import client_ip

allowed_domain_endings = [".gov.uk", ".cloudapps.digital", ".g7uk.org", ".ukcop26.org"]
allowed_domains = ["ukcop26.org"]
CSP_PREFIX = "csp_"


def allowed_document_uri(doc_uri: str) -> bool:
    """

    This tests whether a URL's (complete with scheme) hostname ends with
    one of the allowed_domain_endings values

    # scheme should be present
    >>> allowed_document_uri("www.gov.uk")
    False

    >>> allowed_document_uri("https://www.gov.uk")
    True

    # not in allowed_domain_endings
    >>> allowed_document_uri("http://example.com")
    False

    """

    res = False

    o = urlparse(doc_uri)

    if o:
        for d in allowed_domain_endings:
            if o.hostname and o.hostname.endswith(d):
                res = True
                break
        for d in allowed_domains:
            if o.hostname and o.hostname == d:
                res = True
                break

    return res


def normaliseCsp(input: dict) -> dict:
    """

    >>> t1 = {
    ...   "document-uri": "http://example.com",
    ...   "violated-directive": "style-src cdn.example.com",
    ...   "disposition": "report"
    ... }
    >>> normaliseCsp(t1)
    {'csp_documentURL': 'http://example.com', 'csp_violatedDirective': 'style-src cdn.example.com', 'csp_disposition': 'report'}

    >>> t2 = {
    ...   "documentURL": "https://example.com",
    ...   "disposition": "enforce",
    ...   "effectiveDirective": "frame-src",
    ... }
    >>> normaliseCsp(t2)
    {'csp_documentURL': 'https://example.com', 'csp_disposition': 'enforce', 'csp_effectiveDirective': 'frame-src'}

    """

    normalised = {}
    for k in input:
        originalKey = str(k)

        k = k.replace("-uri", "URL")

        hypenMatch = re.search("-([a-z])", k)
        if hypenMatch:
            k = k.replace(hypenMatch.group(0), hypenMatch.group(1).upper())

        normalised[f"{CSP_PREFIX}{k}"] = input[originalKey]

    return normalised


def report(request: werkzeug.local.LocalProxy, print_out: bool = True) -> dict:
    """
    Extracts a CSP report and prints it to standard out

    >>> from werkzeug.test import EnvironBuilder
    >>> from werkzeug.wrappers import Request

    >>> builder = EnvironBuilder(method='POST')
    >>> env = builder.get_environ()
    >>> req = Request(env)

    >>> t = report(req, print_out=False)
    >>> t["error"]
    'No user-agent given'

    >>> builder = EnvironBuilder(
    ...     method='POST',
    ...     environ_overrides={
    ...         "HTTP_USER_AGENT": "Chrome",
    ...     },
    ... )
    >>> env = builder.get_environ()
    >>> req = Request(env)

    >>> t2 = report(req, print_out=False)
    >>> t2["http_user_agent"]
    'Chrome'

    >>> builder = EnvironBuilder(
    ...     method='POST',
    ...     data=json.dumps({
    ...       "csp-report": {
    ...         "document-uri": "http://example.com/",
    ...       }
    ...     }),
    ...     environ_overrides={
    ...         "HTTP_USER_AGENT": "Chrome",
    ...         "CONTENT_TYPE": "application/json",
    ...     },
    ... )
    >>> env = builder.get_environ()
    >>> req = Request(env)

    >>> t3 = report(req, print_out=False)

    >>> t3["http_content_type"]
    'application/json'

    >>> "csp_documentURL" in t3
    False

    >>> t3["action"]
    'blocked'

    >>> builder = EnvironBuilder(
    ...     method='POST',
    ...     data=json.dumps({
    ...       "csp-report": {
    ...         "document-uri": "http://www.gov.uk/",
    ...       }
    ...     }),
    ...     environ_overrides={
    ...         "HTTP_USER_AGENT": "Chrome",
    ...         "CONTENT_TYPE": "application/json",
    ...     },
    ... )
    >>> env = builder.get_environ()
    >>> req = Request(env)

    >>> t4 = report(req, print_out=False)

    >>> t4["http_content_type"]
    'application/json'

    >>> t4["csp_documentURL"]
    'http://www.gov.uk/'

    >>> t4["action"]
    'allowed'

    >>> builder = EnvironBuilder(
    ...     method='POST',
    ...     data=json.dumps({"blah": 10}),
    ...     environ_overrides={
    ...         "HTTP_USER_AGENT": "Chrome",
    ...         "CONTENT_TYPE": "application/json",
    ...     },
    ... )
    >>> env = builder.get_environ()
    >>> req = Request(env)

    >>> t5 = report(req, print_out=False)

    >>> t5["http_content_type"]
    'application/json'

    >>> t5["error"].startswith("Doesn't look like a valid report")
    True

    >>> t5["action"]
    'blocked'

    """

    log_items = {"time": time.time(), "action": "blocked", "bytes_in": 0}

    try:
        domain = urlparse(request.url).hostname

        # follows the Splunk web CIM:
        # https://docs.splunk.com/Documentation/CIM/latest/User/Web

        log_items = {
            "time": time.time(),
            "action": "blocked",
            "bytes": 0,
            "bytes_in": len(request.data),
            "bytes_out": 0,
            "dest": domain,
            "error": None,
            "http_content_type": None,
            "http_method": request.method,
            "http_referrer": None,
            "http_user_agent": None,
            "src": client_ip(request),
            "status": -1,
            "url": request.url,
            "x_forwarded_for": None,
        }

        if "Content-Type" in request.headers:
            log_items["http_content_type"] = request.headers["Content-Type"]

        if "Referer" in request.headers:
            log_items["http_referrer"] = request.headers["Referer"]

        if "Referrer" in request.headers:
            ref = request.headers["Referrer"]
            log_items["http_referrer"] = ref

        if "HTTP_X_FORWARDED_FOR" in request.environ:
            log_items["x_forwarded_for"] = request.environ["HTTP_X_FORWARDED_FOR"]

        if "User-Agent" in request.headers:
            ua = request.headers["User-Agent"]
            log_items["http_user_agent"] = ua
        else:
            raise Exception("No user-agent given")

        jData = json.loads(str(request.data, "utf-8"))
        cspReport = {}

        # report-uri style:
        if jData and "csp-report" in jData:
            cspReport = normaliseCsp(jData["csp-report"])

        # Report-To style:
        elif jData and type(jData) == list:
            if len(jData) != 1:
                print(
                    json.dumps(
                        {
                            "time": time.time(),
                            "action": "error",
                            "error": "More than one item in list, only handling the first...",
                        }
                    )
                )

            if "documentURL" in jData[0]["body"]:
                cspReport = normaliseCsp(jData[0]["body"])

        if cspReport:
            if f"{CSP_PREFIX}documentURL" in cspReport:
                doc_uri = cspReport[f"{CSP_PREFIX}documentURL"]

                if allowed_document_uri(doc_uri):
                    log_items.update(cspReport)
                    log_items["action"] = "allowed"
                else:
                    raise Exception(f"documentURL not allowed: {doc_uri}")
            else:
                raise Exception("No documentURL in cspReport")
        else:
            try:
                base64_bytes = base64.b64encode(request.get_data())
                body = base64_bytes.decode("ascii")
            except Exception as e:
                body = str(e)

            raise Exception(f"Doesn't look like a valid report: {body}")

    except Exception as e:
        log_items["error"] = str(e)

    log_items["bytes_out"] = len(log_items["action"])
    log_items["bytes"] = log_items["bytes_in"] + log_items["bytes_out"]

    if log_items["action"] == "allowed":
        status = 200
    else:
        status = 406  # Not Acceptable

    log_items["status"] = status

    if print_out:
        print(json.dumps(log_items, default=str))

    return log_items


if __name__ == "__main__":
    """
    If this python is called directly, test using doctest
    """
    import doctest

    doctest.testmod()
