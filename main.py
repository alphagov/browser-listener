#!/usr/bin/env python3

import os
import base64
import time

import csp

from flask import Flask, request, redirect, make_response
from flask_cors import cross_origin
from utils import addHeaders

app = Flask(__name__)
port = os.getenv("PORT", 5000)
repo = "https://github.com/alphagov/browser-listener"


@app.route("/csp-reports", methods=["POST"])
@app.route("/_/csp-reports", methods=["POST"])
@app.route("/.well-known/csp-reports", methods=["POST"])
@cross_origin(origins="*", methods="POST")
def csp_reports():
    resp = csp.report(request)
    return addHeaders(make_response(resp["action"], resp["status"]))


@app.route("/")
def main():
    return redirect(repo, 302)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)
