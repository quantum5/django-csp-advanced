from collections import OrderedDict

from django.core.exceptions import MiddlewareNotUsed
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.utils.decorators import decorator_from_middleware

from csp_advanced.csp import CSPCompiler, InvalidCSPError
from csp_advanced.middleware import AdvancedCSPMiddleware
from csp_advanced.utils import call_csp_dict, is_callable_csp_dict, merge_csp_dict


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
    request = object()
    response = object()

    def make_request_taker(self, output):
        def func(request, response):
            self.assertEqual(request, self.request)
            self.assertEqual(response, self.response)
            return output
        return func

    def test_callable(self):
        self.assertEqual(call_csp_dict(
            self.make_request_taker({'key': 'value'}), self.request, self.response
        ), {'key': 'value'})

    def test_normal_dict(self):
        self.assertEqual(call_csp_dict({'key': 'value'}, None, None), {'key': 'value'})

    def test_callable_entry(self):
        self.assertEqual(call_csp_dict(
            {'key': self.make_request_taker('value')}, self.request, self.response
        ), {'key': 'value'})

    def test_mixed_entry(self):
        self.assertEqual(call_csp_dict({
            'key': self.make_request_taker('value'),
            'name': 'mixed',
        }, self.request, self.response), {
            'key': 'value',
            'name': 'mixed'
        })

    def test_is_callable(self):
        self.assertTrue(is_callable_csp_dict(self.make_request_taker({})))
        self.assertTrue(is_callable_csp_dict({'key': self.make_request_taker('value')}))
        self.assertFalse(is_callable_csp_dict({}))
        self.assertFalse(is_callable_csp_dict({'key': 'value'}))
        self.assertFalse(is_callable_csp_dict(None))


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


class TestMiddleware(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def make_ok_view(self):
        @decorator_from_middleware(AdvancedCSPMiddleware)
        def view(request):
            return HttpResponse('ok')
        return view

    def get_request(self):
        return self.factory.get('/')

    def test_no_csp(self):
        self.assertRaises(MiddlewareNotUsed, AdvancedCSPMiddleware)

    @override_settings(ADVANCED_CSP={'script-src': ['self']})
    def test_new_style(self):
        middleware = AdvancedCSPMiddleware(lambda request: HttpResponse('ok'))
        self.assertEqual(middleware(self.get_request())['Content-Security-Policy'], "script-src 'self'")

    @override_settings(ADVANCED_CSP={'script-src': ['self']})
    def test_setting_csp(self):
        self.assertEqual(self.make_ok_view()(self.get_request())['Content-Security-Policy'], "script-src 'self'")

    @override_settings(ADVANCED_CSP='verbatim bad csp')
    def test_setting_str(self):
        self.assertEqual(self.make_ok_view()(self.get_request())['Content-Security-Policy'], 'verbatim bad csp')

    @override_settings(ADVANCED_CSP={'script-src': ['self']})
    def test_csp_exists(self):
        @decorator_from_middleware(AdvancedCSPMiddleware)
        def view(request):
            response = HttpResponse()
            response['Content-Security-Policy'] = 'verbatim bad csp'
            return response
        self.assertEqual(view(self.get_request())['Content-Security-Policy'], 'verbatim bad csp')

    @override_settings(ADVANCED_CSP={'bad': ['self']})
    def test_invalid_csp(self):
        self.assertFalse('Content-Security-Policy' in self.make_ok_view()(self.get_request()))

    @override_settings(ADVANCED_CSP_REPORT_ONLY={'default-src': ['http://dmoj.ca']})
    def test_setting_csp_report(self):
        self.assertEqual(self.make_ok_view()(self.get_request())['Content-Security-Policy-Report-Only'],
                         "default-src http://dmoj.ca")

    @override_settings(ADVANCED_CSP={'script-src': ['self']},
                       ADVANCED_CSP_REPORT_ONLY={'default-src': ['http://dmoj.ca']})
    def test_setting_both(self):
        response = self.make_ok_view()(self.get_request())
        self.assertEqual(response['Content-Security-Policy'], "script-src 'self'")
        self.assertEqual(response['Content-Security-Policy-Report-Only'], 'default-src http://dmoj.ca')

    @override_settings(ADVANCED_CSP={'script-src': ['self']})
    def test_merge_csp_same(self):
        @decorator_from_middleware(AdvancedCSPMiddleware)
        def view(request):
            response = HttpResponse()
            response.csp = {'script-src': ['https://dmoj.ca']}
            return response
        self.assertEqual(view(self.get_request())['Content-Security-Policy'], "script-src 'self' https://dmoj.ca")

    @override_settings(ADVANCED_CSP={'script-src': ['self']})
    def test_merge_csp_different(self):
        @decorator_from_middleware(AdvancedCSPMiddleware)
        def view(request):
            response = HttpResponse()
            response.csp = {'style-src': ['https://dmoj.ca']}
            return response
        self.assertEqual(sorted(view(self.get_request())['Content-Security-Policy'].split('; ')),
                         ["script-src 'self'", 'style-src https://dmoj.ca'])

    @override_settings(ADVANCED_CSP={'script-src': ['self']})
    def test_override_csp_explicit(self):
        @decorator_from_middleware(AdvancedCSPMiddleware)
        def view(request):
            response = HttpResponse()
            response.csp = {'style-src': ['none'], 'override': True}
            return response
        self.assertEqual(view(self.get_request())['Content-Security-Policy'], "style-src 'none'")

    @override_settings(ADVANCED_CSP={'script-src': ['self']})
    def test_remove_csp(self):
        @decorator_from_middleware(AdvancedCSPMiddleware)
        def view(request):
            response = HttpResponse()
            response.csp = {'override': True}
            return response
        self.assertFalse('Content-Security-Policy' in view(self.get_request()))

    @override_settings(ADVANCED_CSP_REPORT_ONLY={'script-src': ['self']})
    def test_override_csp_to_report_explicit(self):
        @decorator_from_middleware(AdvancedCSPMiddleware)
        def view(request):
            response = HttpResponse()
            response.csp = {'style-src': ['none'], 'override': True}
            return response
        self.assertEqual(view(self.get_request())['Content-Security-Policy-Report-Only'], "style-src 'none'")

    @override_settings(ADVANCED_CSP_REPORT_ONLY={'script-src': ['self']})
    def test_override_csp_report_both_explicit(self):
        @decorator_from_middleware(AdvancedCSPMiddleware)
        def view(request):
            response = HttpResponse()
            response.csp = {'style-src': ['none'], 'override': True}
            response.csp_report = {'script-src': ['none'], 'override': True}
            return response

        response = view(self.get_request())
        self.assertEqual(response['Content-Security-Policy-Report-Only'], "script-src 'none'")
        self.assertFalse('Content-Security-Policy' in response)

    @override_settings(ADVANCED_CSP_REPORT_ONLY={'script-src': ['self']})
    def test_override_csp_report_only_explicit(self):
        @decorator_from_middleware(AdvancedCSPMiddleware)
        def view(request):
            response = HttpResponse()
            response.csp_report = {'script-src': ['none'], 'override': True}
            return response

        response = view(self.get_request())
        self.assertEqual(response['Content-Security-Policy-Report-Only'], "script-src 'none'")
        self.assertFalse('Content-Security-Policy' in response)
