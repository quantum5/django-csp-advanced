import logging
from django.conf import settings
from django.core.exceptions import MiddlewareNotUsed

from csp_advanced.csp import CSPCompiler, InvalidCSPError
from csp_advanced.utils import is_callable_csp_dict, call_csp_dict, merge_csp_dict

log = logging.getLogger(__name__)


class AdvancedCSPMiddleware(object):
    def __init__(self, get_response=None):
        self.get_response = get_response
        self.enforced_csp = getattr(settings, 'ADVANCED_CSP', None) or {}
        self.enforced_csp_is_str = isinstance(self.enforced_csp, str)
        self.enforced_csp_callable = is_callable_csp_dict(self.enforced_csp)
        self.report_csp = getattr(settings, 'ADVANCED_CSP_REPORT_ONLY', None) or {}
        self.report_csp_callable = is_callable_csp_dict(self.report_csp)
        self.report_csp_is_str = isinstance(self.enforced_csp, str)
        self.report_only_csp = not self.enforced_csp

        if not self.enforced_csp and not self.report_csp:
            raise MiddlewareNotUsed()

    def add_csp_header(self, request, response, header, base, can_call, is_str, attrs):
        if header in response:
            return
        if is_str:
            response[header] = base
            return
        csp = call_csp_dict(base, request, response) if can_call else base

        for attr in attrs:
            update = getattr(response, attr, None)
            if update is not None:
                if update.pop('override', False):
                    csp = update
                else:
                    csp = merge_csp_dict(csp, update)
                break

        if not csp:
            return

        try:
            policy = CSPCompiler(csp).compile()
        except InvalidCSPError:
            log.exception('Invalid CSP on page: %s', request.get_full_path())
            return
        response[header] = policy

    def process_response(self, request, response):
        if self.enforced_csp:
            self.add_csp_header(request, response, 'Content-Security-Policy', self.enforced_csp,
                                self.enforced_csp_callable, self.enforced_csp_is_str, ('csp',))
        if self.report_csp:
            self.add_csp_header(request, response, 'Content-Security-Policy-Report-Only',
                                self.report_csp, self.report_csp_callable, self.report_csp_is_str,
                                ('csp_report',) if self.enforced_csp else ('csp_report', 'csp'))
        return response

    def __call__(self, request):
        return self.process_response(request, self.get_response(request))
