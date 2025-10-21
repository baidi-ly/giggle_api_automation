from time import strftime

import pytest
from pandas import DataFrame

from test_case.page_api.admin.admin_quiz_api import AdminQuizApi
from test_case.page_api.school.school_api import SchoolApi
from config import RunConfig
from test_case.page_api.study_plan.study_plan_api import StudyPlanApi

base_url = RunConfig.baseurl

class TestStudyPlanApi:
    """
    学习计划 接口测试用例
    """

    def setup_class(self):
        self.study_plan = StudyPlanApi()
        self.authorization = self.study_plan.get_authorization()
        self.now = strftime("%Y%m%d%H%M%S")