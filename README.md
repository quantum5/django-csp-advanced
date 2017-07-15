# django-csp-advanced [![Build Status](https://img.shields.io/travis/quantum5/django-csp-advanced.svg)](https://travis-ci.org/quantum5/django-csp-advanced) [![Coverage](https://img.shields.io/codecov/c/gh/quantum5/django-csp-advanced.svg)](https://codecov.io/gh/quantum5/django-csp-advanced)

A powerful `Content-Security-Policy` (CSP) middleware for Django. This CSP middleware supports
using a dictionary syntax for CSP, and using callables taking arguments `(request, response)`
to fill in parts of the dictionary.

For example, the following `settings.py` configuration:

```python
ADVANCED_CSP = {
    'block-all-mixed-content': True,
    'frame-src': ['none'],
    'plugin-types': ['application/pdf'],
    'report-uri': '/dev/null',
    'sandbox': ['allow-scripts'],
    'script-src': ['self', 'https://dmoj.ca'],
    'style-src': lambda request, response: ['self'],
    'upgrade-insecure-requests': False,
}
```

generates this CSP (order may differ based on dictionary hashing):

```
style-src 'self'; script-src 'self' https://dmoj.ca; frame-src 'none'; plugin-types application/pdf; block-all-mixed-content; sandbox allow-scripts; report-uri /dev/null
```

Another feature is the ability to augment or replace the CSP from views:

```python
def view(request):
    response = HttpResponse()
    response.csp = {'script-src': ['https://ajax.googleapis.com']}
    return response
```

This will add `https://ajax.googleapis.com` to the list of origins listed for `script-src` to result in something like:

```
...; script-src 'self' https://dmoj.ca https://ajax.googleapis.com; ...
```

You can use `'override': True` to replace the CSP instead:

```python
def view(request):
    response = HttpResponse()
    response.csp = {'script-src': ['self'], 'override': True}
    return response
```

This will replace the CSP with `script-src 'self'`.

You can also set `csp_report` on the response to add entry to the report-only CSP.
Note that neither `csp` or `csp_report` has any effect if their global version is disabled.
However, `csp` will be used to populate `Content-Security-Policy-Report-Only` if there is
no enforced CSP policy configured, but there is a report-only policy.

## Installation

First, install the module with:

```
$ pip install django-csp-advanced
```

Or if you want the latest bleeding edge version:

```
$ pip install -e git://github.com/quantum5/django-csp-advanced.git
```

Then, add `'csp_advanced'` to `INSTALLED_APPS` and `'csp_advanced.middleware.AdvancedCSPMiddleware'`
to `'MIDDLEWARE'` or `'MIDDLEWARE_CLASSES'` depending [on your setup](https://docs.djangoproject.com/en/dev/topics/http/middleware/).

Finally, use either a dictionary or a callable taking `request, response` as either
`ADVANCED_CSP` or `ADVANCED_CSP_REPORT_ONLY`.

Examples:

```python
ADVANCED_CSP = lambda request, response: {'script-src': ['self']}

ADVANCED_CSP_REPORT_ONLY = {'script-src': ['self']}

ADVANCED_CSP = {'style-src': lambda request, response: ['self']}
```

You get the idea.
