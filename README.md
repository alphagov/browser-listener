# Browser Listener

This is a project to have a generic alphagov endpoint for browser statistics
and debugging, like Content-Security-Policy (CSP) reports.

## Content-Security-Policy (CSP)

To use the browswer listener with CSP, set your `Content-Security-Policy` to report to:  
https://browser-listener-10c8e3692d0a.cloudapps.digital/csp-reports

Access to post to the endpoint is restricted by the document URI ending in
certain domains, see [`allowed_domain_endings` in the csp.py](csp.py#L11).

Reports end up in Splunk - contact the cyber security team for access.

### Example report-to header

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

### Example report-uri option in the CSP

You can set (and in addition to the `report-to`) the `report-uri` but this is
[deprecated].
```
Content-Security-Policy: ...; \
  report-uri https://browser-listener-10c8e3692d0a.cloudapps.digital/csp-reports
```

### Example of Python app implementation

You can find an example app here: [example_app/main.py](example_app/main.py)  
Which is deployed here: https://example-for-csp-testing.cloudapps.digital

----

## Development

Changes to `main` get pushed to GOV.UK PaaS using the [deploy.yml workflow].


[deploy.yml workflow]: .github/workflows/deploy.yml
[deprecated]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri
