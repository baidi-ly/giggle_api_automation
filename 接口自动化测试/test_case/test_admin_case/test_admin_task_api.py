import datetime
import sys
import os
from time import strftime

import config
from test_case.page_api.admin.admin_task_api import AdminTaskApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.admin
@pytest.mark.adminTask
class TestAdminUserPreference:

    def setup_class(self):
        self.admin_task = AdminTaskApi()
        self.authorization = self.admin_task.get_admin_authorization()[0]

        self.kid = KidApi()
        self.kid_id = self.kid.getKids(self.authorization)["data"][0]['id']

        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.fixture(scope="class")
    def getSecondekidId(self):
        '''类前置 - 获取kidId'''
        kid_res = self.kid.getKids(self.authorization)['data']
        for kid in kid_res:
            if kid['name'] == "New Kid":
                kid_id = kid['id']
                break
        yield kid_id

    @pytest.mark.smoke
    def test_admin_task_positive_aggregateCourseCompletion_ok(self):
        """统计的是指定日期当天的行为偏好数据-正向用例"""
        res = self.admin_task.aggregateCourseCompletion(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_task_positive_aggregateDailyBehavior_ok(self):
        """手动触发指定日期的互动行为数据聚合任务-正向用例"""
        date = '2025-12-10'
        res = self.admin_task.aggregateDailyBehavior(self.authorization, date)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_task_positive_knowledgeDecay_ok(self):
        """手动触发知识遗忘衰减任务，对最近14天内有活跃学习行为的孩子进行技能掌握度衰减计算-正向用例"""
        res = self.admin_task.knowledgeDecay(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"
