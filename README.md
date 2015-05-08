# flask-secure-headers
Secure Header Wrapper for Flask Applications. This is intended to be a simplified version of the [Twitter SecureHeaders Ruby Gem](https://github.com/twitter/secureheaders) for a Flask Application

## Installation
Install the extension with using pip, or easy_install. [Pypi Link](https://pypi.python.org/pypi/flask-csp)
```bash
$ pip install flask-secure-headers
```

## Included Headers
Header | Purpose | Default
--- | --- | ---
[Content-Security-Policy](http://www.w3.org/TR/CSP2/) | Restrict rescources to prevent XSS/other attacks | default-src 'self'; report-uri /csp_report
[Strict-Transport-Security](https://tools.ietf.org/html/rfc6797) | Prevent downgrade attacks (https->http) | max-age=31536000; includeSubDomains
[X-Permitted-Cross-Domain-Policies](https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html) | Restrict content loaded by flash | master-only
[X-Frame-Options](https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-02) | Prevent content from being framed and clickjacked | sameorigin
[X-XSS-Protection](http://msdn.microsoft.com/en-us/library/dd565647(v=vs.85).aspx) | IE 8+ XSS protection header | 1; mode=block
[X-Content-Type-Options](http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx) | IE MIME-type verification | nosniff
[X-Download-Options](http://msdn.microsoft.com/en-us/library/ie/jj542450(v=vs.85).aspx) | IE 10+ Prevent downloads from opening | noopen


## Usage
