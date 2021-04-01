#!/usr/bin/env python3

import os
import json
import base64
import time
from flask import Flask, request, redirect, make_response
from flask_cors import cross_origin
from urllib.parse import urlparse

app = Flask(__name__)
port = os.getenv("PORT", 5000)

allowed_domain_endings = [".gov.uk", ".cloudapps.digital"]
repo = "https://github.com/alphagov/browser-listener"


def addHeaders(resp):
    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noimageindex"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["Cache-Control"] = "public, max-age=0"
    return resp


def client_ip():
    if request.environ.get("HTTP_X_FORWARDED_FOR") is None:
        ips = request.environ["REMOTE_ADDR"]
    else:
        ips = request.environ["HTTP_X_FORWARDED_FOR"]

    if "," in ips:
        return ips.split(",")[0]
    else:
        return ips


def allowed_document_uri(doc_uri: str) -> bool:
    res = False

    o = urlparse(doc_uri)

    if o:
        for d in allowed_domain_endings:
            if o.hostname and o.hostname.endswith(d):
                res = True
                break

    return res


@app.route("/csp-reports", methods=["POST"])
@app.route("/_/csp-reports", methods=["POST"])
@app.route("/.well-known/csp-reports", methods=["POST"])
@cross_origin(origins="*", methods="POST")
def csp_reports():
    log_items = {"time": time.time(), "action": "blocked"}

    try:
        domain = urlparse(request.url).hostname

        # follows the Splunk web CIM:
        # https://docs.splunk.com/Documentation/CIM/latest/User/Web

        log_items = {
            "time": time.time(),
            "action": "blocked",
            "csp-report": None,
            "bytes": 0,
            "bytes_in": len(request.data),
            "bytes_out": 0,
            "dest": domain,
            "dest_port": port,
            "error": None,
            "http_content_type": None,
            "http_method": request.method,
            "http_referrer": None,
            "http_referrer_domain": None,
            "http_user_agent": None,
            "http_user_agent_length": 0,
            "src": client_ip(),
            "status": -1,
            "url": request.url,
            "url_domain": domain,
            "url_length": len(request.url),
            "vendor_product": repo,
            "x_forwarded_for": None,
        }

        if "Content-Type" in request.headers:
            log_items["http_content_type"] = request.headers["Content-Type"]

        if "Referer" in request.headers:
            log_items["http_referrer"] = request.headers["Referer"]

        if "Referrer" in request.headers:
            ref = request.headers["Referrer"]
            log_items["http_referrer"] = ref
            log_items["http_referrer"] = urlparse(ref).hostname

        if "HTTP_X_FORWARDED_FOR" in request.environ:
            log_items["x_forwarded_for"] = request.environ["HTTP_X_FORWARDED_FOR"]

        if "User-Agent" in request.headers:
            ua = request.headers["User-Agent"]
            log_items["http_user_agent"] = ua
            log_items["http_user_agent_length"] = len(ua)
        else:
            raise Exception("No user-agent given")

        jData = json.loads(str(request.data, "utf-8"))

        # firefox style:
        if jData and "csp-report" in jData:

            if "document-uri" in jData["csp-report"]:
                doc_uri = jData["csp-report"]["document-uri"]

                if allowed_document_uri(doc_uri):
                    log_items["csp-report"] = jData["csp-report"]
                    log_items["action"] = "allowed"
                else:
                    raise Exception(f"document-uri not allowed: {doc_uri}")
            else:
                raise Exception("No document-uri in csp-report")

        # chrome style:
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

            jData = jData[0]

            if "documentURL" in jData["body"]:
                doc_uri = jData["body"]["documentURL"]

                if allowed_document_uri(doc_uri):
                    log_items["csp-report"] = jData["body"]
                    log_items["action"] = "allowed"
                else:
                    raise Exception(f"documentURL not allowed: {doc_uri}")
            else:
                raise Exception("No documentURL in body")

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

    print(json.dumps(log_items, default=str))

    return addHeaders(make_response(log_items["action"], status))


@app.route("/")
def main():
    return redirect(repo, 302)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)
