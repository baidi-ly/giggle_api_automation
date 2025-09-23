import datetime
import sys
import os

import pandas as pd

from test_case.page_api.admin.admin_activity_api import AdminActivityApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminActivity
class TestAdminActivity:

    def setup_class(self):
        self.admin = AdminActivityApi()
        self.authorization = self.admin.get_admin_authorization()



    @pytest.mark.release
    def test_activity_positive_task_ok(self):
        """创建活动任务定义-正向用例"""
        res = self.activity.task(authorization=self.authorization, **{})
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('unauthorized', '未登录', 'missing'),
            ('no_auth', '空token', ''),
            ('expired_token', '鉴权异常-expired_token', 'expired_token'),
            ('invalid_token', '鉴权异常-invalid_token', 'invalid_token'),
        ]
    )
    def test_activity_permission_task(self, input_param, desc, value):
        """创建活动任务定义-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.task(input_param)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

