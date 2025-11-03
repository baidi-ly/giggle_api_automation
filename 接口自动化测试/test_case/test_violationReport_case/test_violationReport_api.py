import pytest
import sys
import os

from test_case.page_api.violationReport.violationReport_api import ViolationReportApi

sys.path.append(os.getcwd())


@pytest.mark.violationReport
class TestViolationReport:
    def setup_class(self):
        self.violationReport = ViolationReportApi()
        self.authorization = self.violationReport.get_authorization()[0]

    def test_violation_report_positive(self):
        """提交违规举报-正向流程"""
        res = self.violationReport.violation_report(self.authorization)
        assert isinstance(res, dict)
        assert res["code"] == 200
        assert res["message"] == "success"
        assert "data" in res