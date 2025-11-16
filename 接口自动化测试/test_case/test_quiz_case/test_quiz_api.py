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

    @pytest.mark.release
    def test_quiz_positive_promotion_submit_ok(self):
        """提交晋级Quiz（批量提交并完成）-正向用例"""
        res = self.quiz.promotion_submit(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_quiz_permission_promotion_submit(self, desc, value):
        """submitPromotionQuiz-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.quiz.promotion_submit(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_quiz_positive_submit_lesson_quiz_ok(self, getkidId):
        """提交课后quiz-正向用例"""
        kidId = getkidId
        courseId = 1
        pl = {
            "kidId": kidId,
            "courseId": courseId,
            "completeTimeStamp": 0,
            "questions": [
                {
                    "quizId": "string",
                    "questionId": 0,
                    "questionSeqNo": 0,
                    "question": "string",
                    "userAnswer": "string",
                    "correctAnswer": "string",
                    "isCorrect": True,
                    "skillTags": [
                        "string"
                    ],
                "completeTimeStamp": 0
                }
            ]
        }
        res = self.quiz.submit_lesson_quiz(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_quiz_permission_submit_lesson_quiz(self, desc, value):
        """提交课后quiz-权限测试"""
        res = self.quiz.submit_lesson_quiz(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
