import sys
import os


from test_case.page_api.admin.admin_quiz_api import AdminQuizApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.admin
@pytest.mark.adminCourse
class TestAdminQuiz:

    def setup_class(self):
        self.admin_quiz = AdminQuizApi()
        self.authorization = self.admin_quiz.get_admin_authorization()[0]

    @pytest.mark.smoke
    def test_admin_quiz_positive_getFix_ok(self):
        """题目difficulty修正-正向用例"""
        res = self.admin_quiz.questionDifficultyFix(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"