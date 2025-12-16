import sys
import os

import pandas as pd

from test_case.page_api.admin.admin_autherranking_api import AdminAutherRankingApi
from test_case.page_api.admin.admin_booktranslation_api import AdminBooktranslationApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminAutherRanking
class TestAdminAutherRanking:

    def setup_class(self):
        self.admin_auther = AdminAutherRankingApi()
        self.authorization = self.admin_auther.get_admin_authorization()[0]

    def test_admin_autherranking_positive_calculate_ok(self):
        """触发作者排名计算-正向用例"""
        res = self.admin_auther.calculate(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == "作者排名计算已完成", f"接口返回data数据异常：{res['data']}"