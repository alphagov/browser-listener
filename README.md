# Browser Listener

This is a project to have a generic alphagov endpoint for browser statistics
and debugging, like Content-Security-Policy (CSP) reports.

## Current Uses

### Content-Security-Policy (CSP)

To use, you'll need to set your `Content-Security-Policy` to report to:  
https://browser-listener-10c8e3692d0a.cloudapps.digital/csp-reports

Reports end up in Splunk - contact the cyber security team for access.

Currently, only domains ending in the following can send reports
(based on the `document-uri`):
- `.gov.uk`
- `.cloudapps.digital`


You should configure CSP using the `Report-To` header and set the `report-to`
attribute in the `Content-Security-Policy` header, like:

```
Report-To: {"group": "csp-endpoint", "max_age": 86400,
             "endpoints": [
               { "url": "https://browser-listener-10c8e3692d0a.cloudapps.digital/csp-reports" }
             ]
           }
Content-Security-Policy: ...; report-to csp-endpoint
```

You can set (and in addition to the `report-to`) the `report-uri` but this is
[deprecated].
```
Content-Security-Policy: ...; \
  report-uri https://browser-listener-10c8e3692d0a.cloudapps.digital/csp-reports
```

You can find an example app here: [example_app/main.py](example_app/main.py)  
Which is deployed here: https://example-for-csp-testing.cloudapps.digital

## Development

Changes to `main` get pushed to GOV.UK PaaS using the [deploy.yml workflow].


[deploy.yml workflow]: .github/workflows/deploy.yml
[deprecated]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri
