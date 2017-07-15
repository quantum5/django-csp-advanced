from collections import OrderedDict

from django.test import SimpleTestCase

from csp import CSPCompiler, InvalidCSPError
from utils import callable_csp_dict, merge_csp_dict


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


class CallableCSPDictTest(SimpleTestCase):
    def test_callable(self):
        self.assertEqual(callable_csp_dict(lambda: {'key': 'value'}), {'key': 'value'})

    def test_normal_dict(self):
        self.assertEqual(callable_csp_dict({'key': 'value'}), {'key': 'value'})

    def test_callable_entry(self):
        self.assertEqual(callable_csp_dict({'key': lambda: 'value'}), {'key': 'value'})

    def test_mixed_entry(self):
        self.assertEqual(callable_csp_dict({
            'key': lambda: 'value',
            'name': 'mixed',
        }), {
            'key': 'value',
            'name': 'mixed'
        })


class MergeCSPDictTest(SimpleTestCase):
    def test_null(self):
        test = {'key': 'value'}
        self.assertEqual(merge_csp_dict(test, {}), test)

    def test_distinct_key(self):
        self.assertEqual(merge_csp_dict({'spam': 1}, {'ham': 2}), {'spam': 1, 'ham': 2})

    def test_scalar_override(self):
        self.assertEqual(merge_csp_dict({'spam': 1}, {'spam': 2}), {'spam': 2})

    def test_list_override(self):
        orig = [1]
        self.assertEqual(merge_csp_dict({'spam': orig}, {'spam': [2]}), {'spam': [1, 2]})
        self.assertEqual(orig, [1])

    def test_set_override(self):
        orig = {1}
        self.assertEqual(merge_csp_dict({'spam': orig}, {'spam': [2]}), {'spam': {1, 2}})
        self.assertEqual(orig, {1})

    def test_tuple_override(self):
        self.assertEqual(merge_csp_dict({'spam': (1,)}, {'spam': (2,)}), {'spam': (1, 2)})
