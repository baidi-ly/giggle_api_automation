import pytest

from test_case.page_api.admin.admin_quiz_api import AdminQuizApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.quiz.quiz_api import QuizApi
from config import RunConfig
from test_case.page_api.reward.reward_api import RewardApi

base_url = RunConfig.baseurl
expired_token = RunConfig.expired_token

class TestRewardApi:
    """
    school 接口测试用例
    """

    def setup_class(self):
        self.reward = RewardApi()
        self.authorization = self.reward.get_authorization()[0]

    @pytest.mark.smoke
    def test_play_zone_random_line_drawing_word(self, kid_data_session):
        """分页查询支出记录列表-正向用例"""
        kid_id = kid_data_session[0]
        res = self.reward.continuousProgress(self.authorization, kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"