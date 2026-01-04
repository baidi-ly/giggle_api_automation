import sys
import os
from time import strftime

import config
from test_case.page_api.admin.admin_statistics_api import AdminStatisticsApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.admin
@pytest.mark.adminStatistics
class TestAdminStatistics:

    def setup_class(self):
        self.admin_statistics = AdminStatisticsApi()
        self.auth_admin = self.admin_statistics.get_admin_authorization()[0]

        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.smoke
    def test_admin_statistics_positive_getGuestRetention_ok(self):
        """获取游客留存统计数据-正向用例"""
        res = self.admin_statistics.getGuestRetention(self.auth_admin)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"