from itertools import chain


class InvalidCSPError(ValueError):
    pass


class CSPCompiler(object):
    CSP_LISTS = {
        # Fetch directives:
        'connect-src',
        'child-src',
        'default-src',
        'font-src',
        'frame-src',
        'img-src',
        'manifest-src',
        'media-src',
        'object-src',
        'script-src',
        'style-src',
        'worker-src',

        # Navigation directives:
        'form-action',
        'frame-ancestors',

        # Document directives:
        'base-uri',
        'plugin-types',
    }

    CSP_BOOLEAN = {
        'upgrade-insecure-requests',
        'block-all-mixed-content',
    }

    CSP_FETCH_SPECIAL = {
        'self',
        'none',
        'unsafe-inline',
        'unsafe-eval',
        'strict-dynamic',
    }

    CSP_PREFIX_SPECIAL = (
        'nonce-',
        'sha256-',
        'sha384-',
        'sha512-'
    )

    CSP_SANDBOX_VALID = {
        'allow-forms',
        'allow-modals',
        'allow-orientation-lock',
        'allow-pointer-lock',
        'allow-popups',
        'allow-popups-to-escape-sandbox',
        'allow-presentation',
        'allow-same-origin',
        'allow-scripts',
        'allow-top-navigation',
    }

    CSP_REQUIRE_SRI_VALID = {
        'script',
        'style',
        'script style',
    }

    def __init__(self, csp_dict):
        self.csp = csp_dict

    def compile(self):
        pieces = []
        for name, value in self.csp.items():
            if name in self.CSP_LISTS:
                if value:
                    pieces.append(self.compile_list(name, value))
            elif name in self.CSP_BOOLEAN:
                if value:
                    pieces.append(name)
            elif name == 'sandbox':
                if value:
                    pieces.append(self.compile_sandbox(value))
            elif name == 'report-uri':
                pieces.append(self.compile_report_uri(value))
            elif name == 'require-sri-for':
                pieces.append(self.compile_require_sri_for(value))
            else:
                raise InvalidCSPError('Unknown directive: %s' % (name,))
        return '; '.join(pieces)

    def compile_list(self, name, value_list):
        self.ensure_list(name, value_list)
        values = [name]
        for value in value_list:
            if value in self.CSP_FETCH_SPECIAL or value.startswith(self.CSP_PREFIX_SPECIAL):
                values.append("'%s'" % value)
            else:
                values.append(value)
        return ' '.join(values)

    def compile_sandbox(self, values):
        self.ensure_list('sandbox', values)
        for value in values:
            if value not in self.CSP_SANDBOX_VALID:
                raise InvalidCSPError('Unknown sandbox value: %s' % (value,))
        return ' '.join(chain(['sandbox'], values))

    def compile_report_uri(self, value):
        self.ensure_str('report-uri', value)
        return 'report-uri %s' % value

    def compile_require_sri_for(self, value):
        self.ensure_str('require-sri-for', value)
        if value not in self.CSP_REQUIRE_SRI_VALID:
            raise InvalidCSPError('Unknown require-sri-for value: %s' % (value,))
        return 'require-sri-for %s' % value

    @staticmethod
    def ensure_list(name, value):
        if not isinstance(value, (list, tuple, set)):
            raise InvalidCSPError('Values for %s must be list-like type, not %s', (name, type(value)))

    @staticmethod
    def ensure_str(name, value):
        if not isinstance(value, str):
            raise InvalidCSPError('Values for %s must be a string type, not %s', (name, type(value)))
