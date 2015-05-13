# flask-secure-headers
Secure Header Wrapper for Flask Applications. This is intended to be a simplified version of the [Twitter SecureHeaders Ruby Gem](https://github.com/twitter/secureheaders)

## Installation
Install the extension with using pip, or easy_install. [Pypi Link](https://pypi.python.org/pypi/flask-secure-headers)
```bash
$ pip install flask-secure-headers
```

## Included Headers
Header | Purpose | Default Policy
--- | --- | ---
[Content-Security-Policy (CSP)](http://www.w3.org/TR/CSP2/) | Restrict rescources to prevent XSS/other attacks | *default-src 'self'; report-uri /csp_report*
[Strict-Transport-Security (HSTS)](https://tools.ietf.org/html/rfc6797) | Prevent downgrade attacks (https to http) | *max-age=31536000; include_subdomains*
[X-Permitted-Cross-Domain-Policies](https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html) | Restrict content loaded by flash | *master-only*
[X-Frame-Options](https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-02) | Prevent content from being framed and clickjacked | *sameorigin*
[X-XSS-Protection](http://msdn.microsoft.com/en-us/library/dd565647(v=vs.85).aspx) | IE 8+ XSS protection header | *1; mode=block*
[X-Content-Type-Options](http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx) | IE 9+ MIME-type verification | *nosniff*
[X-Download-Options](http://msdn.microsoft.com/en-us/library/ie/jj542450(v=vs.85).aspx) | IE 10+ Prevent downloads from opening | *noopen*
[Public-Key-Pins (HPKP)]() | Associate host with expected CA or public key | *max_age=5184000; include_subdomains; report_uri=/hpkp_report [... no default pins]*


## Usage

Each header policy is represented by a dict of paramaters. [View default policies](/flask_secure_headers/core.py).
* Policies with a key/value pair are represented as {key:value}
  * Ex: *{'mode':'block'}* becomes *'mode=block'*
* Policies with just a string value are represented as {'value':parameter}
  * Ex: *{'value':'noopen'}* becomes *'noopen'*
* Policies with additional string values are represented as {value:Bool}
  * Ex: *{'maxage':1,'include_subdomains':True,'preload':False}* becomes *'maxage=1 include_subdomains'*
* CSP is represented as a list inside the dict {cspPolicy:[param,param]}. 
  * Ex: *{'script-src':['self']}* becomes *"script-src 'self'"*
  * self, none, nonce-* ,sha*, unsafe-inline, etc are automatically encapsulated
* HPKP pins are represented by a list of dicts under the 'pins' paramter {'pins':[{hashType:hash}]}
  * Ex: {'pins':[{'sha256':'test123'},{'sha256':'testABCD'}]} becomes 'pin-sha256=test1234; pin-sha256=testABCD'

### Configuration

To load the headers into your flask app, import the function:
```python
from flask_secure_headers.core import Secure_Headers
...
sh = Secure_Headers()
```

There are two methods to change the default policies that will persist throughout the application: update(), rewrite()
* Update will add to an existing policy
* Rewrite will replace a policy

To update/rewrite, pass a dict in of the desired values into the desired method:
```python
""" update """
sh.update({'CSP':{'script-src':['self','code.jquery.com']}}) 
# Content-Security-Policy: script-src 'self' code.jquery.com; report-uri /csp_report; default-src 'self
sh.update(
 {'X_Permitted_Cross_Domain_Policies':{'value':'all'}},
 {'HPKP':{'pins':[{'sha256':'1234'}]}}
)
# X-Permitted-Cross-Domain-Policies: all
# Public-Key-Pins: max_age=5184000; include_subdomains; report_uri=/hpkp_report; pin-sha256=1234

""" rewrite """
sh.rewrite({'CSP':{'default-src':['none']}})
# Content-Security-Policy: default-src 'none'
```

A policy can also be removed by passing None as the value:
```python
sh.rewrite({'CSP':None})
# there will be no CSP header
```

For non-CSP headers that contain multiple paramaters (HSTS and X-XSS-Protection), any paramter other than the first can be removed by passing a value of False:
```python
sh.update({'X-XSS-Protection':{'value':1,'mode':False}})
# will produce X-XSS-Protection: 1

sh.update({'HSTS':{'maxage':1,'include_subdomains':True,'preload':False}})
# will produce Strict-Transport-Security: maxage=1; include_subdomains
```

Notes:
* Header keys can be written using either '_' or '-', but are case sensitive 
  * Acceptable: 'X-XSS-Protection','X_XSS_Protection'
  * Unacceptable: 'x-xss-protection'
* 3 headers are abreviated
  * CSP = Content-Security-Policy
  * HSTS = Strict-Transport-Security
  * HPKP = Public-Key-Pins

### Creating the Wrapper
Add the @sh.wrapper() decorator after your app.route(...) decorators for each route to create the headers based on the policy you have created using the update/remove methods (or the default policy if those were not used)
```python
@app.route('/')
@sh.wrapper()
def index():
  ...
```

The wrapper() method can also be passed a dict in the same format as update/remove to change policies. These policy changes will only effect that specific route.

A couple notes:
* Changes here will always update the policy instead of rewrite
* CSP policy and HPKP pin lists will be merged, not overwritten. See comment below for example.
```python
@app.route('/')
@sh.wrapper({
 'CSP':{'script-src':['sha1-klsdjfkl232']},
 'HPKP':{'pins':[{'sha256':'ABCD'}]}
})
def index():
  ...
# CSP will contain "script-src 'self' 'sha1-klsdjfkl232'"
# HPKP will contain "pins-sha256=1234; pins-sha256=ABCD;"
```

Policies can also be removed from a wrapper:
```python
@app.route('/')
@sh.wrapper({'CSP':None,'X-XSS-Protection':None})
def index():
  ...
# this route will not include Content-Security-Policy or X-XSS-Protection Headers
```
