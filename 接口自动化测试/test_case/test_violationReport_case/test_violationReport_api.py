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

    @pytest.mark.release
    def test_violation_report_positive(self):
        """提交违规举报-正向流程"""
        content = "自动化举报测试"
        images = ["https://xx.com/demo.jpg"]
        res = self.violationReport.report(self.authorization, content=content, images=images)
        assert isinstance(res, dict)
        assert res["code"] == 200
        assert res["message"] == "success"
        assert "data" in res

    @pytest.mark.release
    @pytest.mark.parametrize("content", ['', None])
    def test_violation_report_required_content(self, content):
        """内容必填校验"""
        res = self.violationReport.report(self.authorization, content=content, code=400)
        assert isinstance(res, dict)
        assert res["code"] == 400

    @pytest.mark.release
    @pytest.mark.parametrize("authorization, code", [
        ("", 401),
        ("invalid_token", 401),
    ])
    def test_violation_report_permission(self, authorization, code):
        """权限校验"""
        res = self.violationReport.report(authorization, content="hi", code=code)
        assert isinstance(res, dict)
        assert res["code"] == code