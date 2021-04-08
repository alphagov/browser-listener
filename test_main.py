from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse
from main import app
import json

c = Client(app, BaseResponse)


def test_main():
    resp = c.get("/")
    assert resp.status_code == 302
    assert "github" in resp.headers["Location"]


def test_csp_reports_bad():
    resp = c.post("/csp-reports")
    assert resp.status_code == 406


def test_csp_reports_good(capsys):
    resp = c.post(
        "/csp-reports",
        data=json.dumps({"csp-report": {"document-uri": "https://www.gov.uk"}}),
        environ_base={"HTTP_USER_AGENT": "Chrome"},
    )

    captured = capsys.readouterr()

    assert resp.status_code == 200
    assert len(captured.out) > 0

    jTest = json.loads(captured.out)
    assert "csp_documentURL" in jTest
