
import sys
import os

from test_case.page_api.admin.admin_learning_api import AdminLearningApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminFlashcard
class TestAdminFlashcard:

    def setup_class(self):
        self.admin_learning = AdminLearningApi()
        self.authorization = self.admin_learning.get_admin_authorization()[0]

    @pytest.mark.skip('临时测试接口')
    def test_admin_learningstats_positive_ok(self):
        """创建学习计划（包含单元和内容）-正向用例"""
        res = self.admin_learning.trigger_weekly_reports(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"