import datetime
import random
import string
import sys
import os
from time import strftime

import pandas as pd
from pandas import DataFrame

import config
from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.admin.admin_grayscale_api import AdminGrayscaleApi
from test_case.page_api.admin.admin_levelskills_api import AdminLevelskillsApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.Admin
@pytest.mark.AdminGrayscale
class TestAdminGrayscale:

    def setup_class(self):
        self.admin = AdminGrayscaleApi()
        self.admin_authorization = self.admin.get_admin_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.smoke
    def test_admin_courseinteraction_positive_getList_ok(self):
        """查询课程交互类型映射列表-正向用例"""
        userKeys = ["cQ1YSvuHQkGi5Qj91cHEP9"]
        res = self.admin.grayscale_batch_set(self.admin_authorization, userKeys)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"