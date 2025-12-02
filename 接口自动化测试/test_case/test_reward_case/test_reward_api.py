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

