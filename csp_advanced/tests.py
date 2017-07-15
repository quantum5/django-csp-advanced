from collections import OrderedDict

from django.test import SimpleTestCase

from csp import CSPCompiler, InvalidCSPError


class CSPCompileTest(SimpleTestCase):
    def test_fetch(self):
        self.assertEqual(CSPCompiler({
            'script-src': ['self', 'https://dmoj.ca', 'nonce-123'],
        }).compile(), "script-src 'self' https://dmoj.ca 'nonce-123'")

        with self.assertRaises(InvalidCSPError):
            CSPCompiler({
                'script-src': 'https://dmoj.ca',
            }).compile()

    def test_sandbox(self):
        self.assertEqual(CSPCompiler({
            'sandbox': ['allow-same-origin', 'allow-scripts'],
        }).compile(), "sandbox allow-same-origin allow-scripts")

        with self.assertRaises(InvalidCSPError):
            CSPCompiler({
                'sandbox': ['allow-invalid', 'allow-scripts'],
            }).compile()

        with self.assertRaises(InvalidCSPError):
            CSPCompiler({
                'sandbox': 'allow-scripts',
            }).compile()

    def test_report_uri(self):
        self.assertEqual(CSPCompiler({
            'report-uri': '/dev/null',
        }).compile(), "report-uri /dev/null")

        with self.assertRaises(InvalidCSPError):
            CSPCompiler({'report-uri': []}).compile()

    def test_require_sri_for(self):
        self.assertEqual(CSPCompiler({
            'require-sri-for': 'script style',
        }).compile(), "require-sri-for script style")

        with self.assertRaises(InvalidCSPError):
            CSPCompiler({'require-sri-for': []}).compile()

        with self.assertRaises(InvalidCSPError):
            CSPCompiler({'require-sri-for': 'bad'}).compile()

    def test_upgrade_insecure_requests(self):
        self.assertEqual(CSPCompiler({
            'upgrade-insecure-requests': True,
        }).compile(), "upgrade-insecure-requests")

        self.assertEqual(CSPCompiler({
            'upgrade-insecure-requests': False,
        }).compile(), '')

    def test_integration(self):
        self.assertEqual(CSPCompiler(OrderedDict([
            ('style-src', ['self']),
            ('script-src', ['self', 'https://dmoj.ca']),
            ('frame-src', ['none']),
            ('plugin-types', ['application/pdf']),
            ('block-all-mixed-content', True),
            ('upgrade-insecure-requests', False),
            ('sandbox', ['allow-scripts']),
            ('report-uri', '/dev/null')
        ])).compile(),
            "style-src 'self'; script-src 'self' https://dmoj.ca; frame-src 'none'; "
            "plugin-types application/pdf; block-all-mixed-content; sandbox allow-scripts; "
            "report-uri /dev/null")
