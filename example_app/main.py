#!/usr/bin/env python3

import os
import json
from flask import Flask, request, redirect, make_response

app = Flask(__name__)
port = os.getenv("PORT", 5000)
repurl = "https://browser-listener-10c8e3692d0a.cloudapps.digital/csp-reports"
repo = "https://github.com/alphagov/browser-listener"


def addHeaders(resp):
    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noimageindex"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["Cache-Control"] = "public, max-age=0"
    resp.headers["Report-To"] = json.dumps(
        {"group": "csp-endpoint", "max_age": 86400, "endpoints": [{"url": repurl}]}
    )
    resp.headers[
        "Content-Security-Policy"
    ] = f"default-src 'none'; report-to csp-endpoint; report-uri {repurl}"
    return resp


@app.route("/")
def main():
    return addHeaders(
        make_response(
            f"""
    <div>
    Hey there, this is test for
    <a href="{repo}">{repo}</a>
    to invoke a Content-Security-Policy violation.
    </div>
    <div>
    This gif should fail:
    </div>
    <iframe src="https://giphy.com/embed/l0MYzwTebntNEii4M" width="480" height="480" frameBorder="0" class="giphy-embed" allowFullScreen></iframe>
    <div>
    <i><a href="http://gph.is/2iMxzXI">Hello World Smile GIF By Lame Kids Club</a></i>
    </div>
    """
        )
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)
