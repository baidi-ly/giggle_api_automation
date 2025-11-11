import pytest

from test_case.page_api.admin.admin_quiz_api import AdminQuizApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.quiz.quiz_api import QuizApi
from config import RunConfig

base_url = RunConfig.baseurl
expired_token = RunConfig.expired_token

class TestSchoolApi:
    """
    school 接口测试用例
    """

    def setup_class(self):
        self.quiz = QuizApi()
        self.kid = KidApi()
        self.admin = AdminQuizApi()
        self.authorization = self.quiz.get_authorization()[0]

    @pytest.fixture(scope="class")
    def getkidId(self):
        '''类前置 - 获取kidId'''
        kid_res = self.kid.getKids(self.authorization)
        yield kid_res['data'][0]['id']

    @pytest.mark.smoke
    def test_quiz_positive_quizId_detail_ok(self):
        """查询指定quiz的详情-正向用例"""
        res_quiz = self.admin.quiz_list(self.authorization)['data']['content'][0]
        quizId, quizData = res_quiz['id'], res_quiz['quizData']
        res = self.quiz.quizId_detail(self.authorization, quizId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"