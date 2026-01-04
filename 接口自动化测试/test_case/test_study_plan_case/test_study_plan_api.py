from datetime import time
from time import strftime
import time

import pytest

from test_case.page_api.admin.admin_flashcards_api import AdminFlashcardsApi
from test_case.page_api.admin.admin_studyplan_api import AdminStudyplanApi
from config import RunConfig
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.study_plan.study_plan_api import Study_planApi

base_url = RunConfig.baseurl

class TestStudyPlanApi:
    """
    学习计划 接口测试用例
    """

    def setup_class(self):
        self.study_plan = Study_planApi()
        self.admin_flashcard = AdminFlashcardsApi()
        self.admin_study = AdminStudyplanApi()
        self.kid = KidApi()
        self.authorization = self.study_plan.get_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

        # 新增闪卡
        quiz_name = 'dibo_test_flashcards' + self.now
        quiz_res = self.admin_flashcard.flashcards_create(self.authorization, name=quiz_name)["data"]
        self.contentId = quiz_res["id"]
        # 创建学习计划
        study_plan_name = 'dibo_test_study_plan' + self.now
        contents = [
            {
                "contentId": self.contentId,
                "contentType": "flash_card",
                "difficulty": "easy",
                "name": study_plan_name,
                "sortOrder": 1,
                "wordCount": 20,
                "contentConfig": {
                    "words": ["apple", "banana", "cat", "dog"]
                }
            }
        ]
        self.studyPlanId = self.admin_study.study_plan_create(self.authorization, contents)["data"]["id"]
        # 启用学习计划状态
        res = self.admin_study.putStatus(self.authorization, studyPlanId=self.studyPlanId, status=1)
        assert res['message'] == 'success', '启用学习计划状态失败！'
        # 获取kidId
        self.kidId = self.kid.getKids(self.authorization)["data"][0]["id"]

    def teardown_class(self):
        # 获取当前所有禁用的学习计划列表
        studyPlans_res0 = self.admin_study.study_plan_list(self.authorization, category='vocabulary', status=0)['data']['content']
        # 获取当前所有启用的学习计划列表
        studyPlans_res1 = self.admin_study.study_plan_list(self.authorization, category='vocabulary', status=1)['data']['content']
        for studyPlan in studyPlans_res0:
            if studyPlan["name"].startswith('dibo_test'):
                try:
                    # 删除测试学习计划包
                    res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlan["id"])
                    assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
                    assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
                except Exception as e:
                    print(e)
        for studyPlan in studyPlans_res1:
            if studyPlan["name"].startswith('dibo_test'):
                try:
                    # 删除测试学习计划包
                    res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlan["id"])
                    assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
                    assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
                except Exception as e:
                    print(e)

    @pytest.mark.smoke
    def test_study_plan_positive_getList_ok(self):
        """学习计划包列表-正向用例"""
        res = self.study_plan.study_plan_list(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.fixture(scope='function')
    def two_study_plans(self):
        """创建两条学习计划用于优先级上下验证，测试结束删除"""
        # 创建学习计划
        study_plan_name = 'dibo_test_study_plan' + self.now
        contents = [
            {
                "contentId": self.contentId,
                "contentType": "flash_card",
                "difficulty": "easy",
                "name": study_plan_name,
                "sortOrder": 1,
                "wordCount": 20,
                "contentConfig": {
                    "words": ["apple", "banana", "cat", "dog"]
                }
            }
        ]
        resp1 = self.admin_study.study_plan_create(self.authorization, contents)
        assert isinstance(resp1, dict), f"create_study_plan 返回类型异常: {type(resp1)}"
        assert 'data' in resp1, f"create_study_plan 返回没有 data: {resp1}"
        id1 = resp1['data'].get('id')
        assert id1 is not None, f"创建学习计划1失败, resp={resp1}"

        study_plan_name = 'dibo_test_study_plan1' + self.now
        contents = [
            {
                "contentId": self.contentId,
                "contentType": "flash_card",
                "difficulty": "easy",
                "name": study_plan_name,
                "sortOrder": 1,
                "wordCount": 20,
                "contentConfig": {
                    "words": ["apple", "banana", "cat", "dog"]
                }
            }
        ]
        resp2 = self.admin_study.study_plan_create(self.authorization, contents)
        assert isinstance(resp2, dict) and 'data' in resp2
        id2 = resp2['data'].get('id')
        assert id2 is not None, f"创建学习计划2失败, resp={resp2}"

        yield id1, id2

        # cleanup
        d1 = self.admin_study.delete_studyPlan(self.authorization, id1)
        d2 = self.admin_study.delete_studyPlan(self.authorization, id2)
        assert isinstance(d1, dict) and 'code' in d1
        assert isinstance(d2, dict) and 'code' in d2

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_study_plan_permission_getList(self, desc, value):
        """学习计划包列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.study_plan.study_plan_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_study_plan_positive_studyPlan_details_ok(self):
        """学习计划包详情-正向用例"""
        res = self.study_plan.studyPlan_details(self.authorization, self.studyPlanId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_study_plan_permission_studyPlan_details(self, desc, value):
        """学习计划包详情-权限测试"""
        res = self.study_plan.studyPlan_details(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 400, 100006),
            ('float', 12.34, 400, 100006),
            ('boolean', True, 400, 100006),
            ('negative', -123, 200, 100150),
            ('array', [1, 2, 3], 400, 100006),
            ('object', {'key': 'value'}, 400, 100006),
            ('special_chars', '!@#$%^&*()', 400, 100006),
            ('emoji', 'test_emoji', 400, 100006),
        ]
    )
    def test_study_plan_format_studyPlan_details_studyPlanId(self, desc, value, code, code_res):
        """学习计划包详情-数据格式测试(studyPlanId)"""
        try:
            res = self.study_plan.studyPlan_details(self.authorization, studyPlanId=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"
        elif code_res == 100006:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【'not found'】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"
        elif code_res == 100150:
            assert res['code'] == 100150, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'Study plan not found', f"接口返回message信息异常: 预期【'Study plan not found'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 200),
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_study_plan_boundary_studyPlan_details_studyPlanId(self, desc, value, code):
        """学习计划包详情-边界值测试(studyPlanId)"""
        res = self.study_plan.studyPlan_details(self.authorization, studyPlanId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100150, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'Study plan not found', f"接口返回message信息异常: 预期【'Study plan not found'】，实际【{res['message']}】"
        assert res['data'] == 'Study plan not found', f"接口返回data数据异常：预期【'Study plan not found'】,{res['data']}"

    def test_study_plan_scenario_studyPlan_details_invalid_studyPlanId(self):
        """学习计划包详情-场景异常-无效的studyPlanId"""
        studyPlanId = 999999999
        res = self.study_plan.studyPlan_details(self.authorization, studyPlanId=studyPlanId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100150, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'Study plan not found', f"接口返回message信息异常: 预期【'Study plan not found'】，实际【{res['message']}】"
        assert res['data'] == 'Study plan not found', f"接口返回data数据异常：预期【'Study plan not found'】,{res['data']}"

    @pytest.mark.smoke
    def test_study_plan_positive_getUnits_ok(self):
        """学习计划单元列表-正向用例"""
        res = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, self.kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_study_plan_permission_getUnits(self, desc, value):
        """学习计划单元列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.study_plan.study_plan_units(value, self.studyPlanId, self.kidId, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 400, 100006),
            ('float', 12.34, 400, 100006),
            ('boolean', True, 400, 100006),
            ('negative', -123, 500, 500),
            ('array', [1, 2, 3], 200, 100105),
            ('object', {'key': 'value'}, 400, 100006),
            ('special_chars', '!@#$%^&*()', 403, ''),
            ('emoji', 'test_emoji', 400, 100006),
        ]
    )
    def test_study_plan_format_getUnits_kidId(self, desc, value, code, code_res):
        """学习计划单元列表-数据格式测试(kidId)"""
        try:
            res = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, kidId=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"
        elif code_res == 100006:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【'not found'】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"
        elif code_res == 100150:
            assert res['code'] == 100150, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'Study plan not found', f"接口返回message信息异常: 预期【'Study plan not found'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_study_plan_boundary_getUnits_kidId(self, desc, value, code):
        """学习计划单元列表-边界值测试(kidId)"""
        res = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, kidId=value, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if desc != 'min':
            assert res['code'] == 100105, f"接口返回状态码异常: 预期【100105】，实际【{res['code']}】"
            assert res['message'] == 'Kid id not exist', f"接口返回message信息异常: 预期【'Kid id not exist'】，实际【{res['message']}】"
            assert res['data'] == 'Kid id not exist', f"接口返回data数据异常：{res['data']}"
        else:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【100105】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_study_plan_scenario_getUnits_invalid_kidId(self):
        """学习计划单元列表-场景异常-无效的kidId"""
        kidId = 999999999
        res = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100105, f"接口返回状态码异常: 预期【100105】，实际【{res['code']}】"
        assert res['message'] == 'Kid id not exist', f"接口返回message信息异常: 预期【'Kid id not exist'】，实际【{res['message']}】"
        assert res['data'] == 'Kid id not exist', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_study_plan_positive_getContents_ok(self):
        """学习计划单元内容列表-正向用例"""
        unitId = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, self.kidId)['data'][0]['id']
        res = self.study_plan.study_plan_contents(self.authorization, unitId, self.kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_study_plan_permission_getContents(self, desc, value):
        """学习计划单元内容列表-权限测试"""
        unitId = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, self.kidId)['data'][0]['id']
        res = self.study_plan.study_plan_contents(value, unitId, self.kidId, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_study_plan_scenario_getContents_invalid_kidId(self):
        """学习计划单元内容列表-场景异常-无效的kidId"""
        kidId = 999999999
        unitId = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, self.kidId)['data'][0]['id']
        res = self.study_plan.study_plan_contents(self.authorization, unitId, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100105, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'Kid id not exist', f"接口返回message信息异常: 预期【'Kid id not exist'】，实际【{res['message']}】"
        assert res['data'] == 'Kid id not exist', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_study_plan_positive_getProgress_ok(self):
        """获取学习计划进度-正向用例"""
        res = self.study_plan.study_plan_progress(self.authorization, self.studyPlanId, self.kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_study_plan_permission_getProgress(self, desc, value):
        """获取学习计划进度-权限测试"""
        res = self.study_plan.study_plan_progress(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_study_plan_scenario_getProgress_invalid_kidId(self):
        """获取学习计划进度-场景异常-无效的kidId"""
        kidId = 999999999
        res = self.study_plan.study_plan_progress(self.authorization, self.studyPlanId, kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100105, f"接口返回状态码异常: 预期【100105】，实际【{res['code']}】"
        assert res['message'] == 'Kid id not exist', f"接口返回message信息异常: 预期【'Kid id not exist'】，实际【{res['message']}】"
        assert res['data'] == 'Kid id not exist', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_study_plan_permission_complete(self, desc, value):
        """完成学习计划内容-权限测试"""
        res = self.study_plan.studyplan_content_complete(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_study_positive_claimReward_ok(self):
        """领取学习计划奖励-正向用例"""
        # 学习计划单元列表
        unitId = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, self.kidId)['data'][0]['id']
        # 学习计划单元内容列表
        studyPlanContentId = self.study_plan.study_plan_contents(self.authorization, unitId, self.kidId)['data'][0]['id']
        # 完成学习计划内容
        pl = {
            "completionTime": "2025-10-21T08:36:11.811Z",
            "kidId": self.kidId,
            "learningDuration": 0,
            "studyPlanContentId": studyPlanContentId,
            "studyPlanId": self.studyPlanId,
            "studyPlanUnitId": unitId
        }
        self.study_plan.studyplan_content_complete(self.authorization, **pl)
        # 领取学习计划奖励
        res = self.study_plan.claimReward(self.authorization, int(self.studyPlanId), self.kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == {'giggles': 50, 'rewardClaimed': True}, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_study_permission_claimReward(self, desc, value):
        """领取学习计划奖励-权限测试"""
        res = self.study_plan.claimReward(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_study_scenario_claimReward_invalid_kidId(self):
        """领取学习计划奖励-场景异常-无效的kidId"""
        kidId = 99999
        res = self.study_plan.claimReward(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100105, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'Kid id not exist', f"接口返回message信息异常: 预期【Kid id not exist】，实际【{res['message']}】"
        assert res['data'] == 'Kid id not exist', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing', 'missing', 200),
            ('empty', "", 200),
            ('null', None, 200),
        ]
    )
    def test_study_required_claimReward_kidId(self, desc, value, code):
        """查询指定类型下的故事书标签列表-必填字段测试(kidId)"""
        if desc == 'missing':
            pl = {'pop_items': 'kidId'}
        else:
            pl = {'kidId': value}
        res = self.study_plan.claimReward(self.authorization, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100105, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'Kid id not exist', f"接口返回message信息异常: 预期【Kid id not exist】，实际【{res['message']}】"
        assert res['data'] == 'Kid id not exist', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_study_plan_move_down_then_up_detaile(self, two_study_plans):
        # 创建两条学习计划用于优先级上下验证
        plan1_id, plan2_id = two_study_plans

        # 记录操作时间窗口，用于校验 dbModifyTime
        before_op_ts = int(time.time() * 1000)

        # 1) 对第二条执行下移：应返回该记录的 id、priority（int 且 >=0）、dbModifyTime（>= before_op_ts）
        down_resp = self.admin_study.move_priority_down(self.authorization, plan2_id)
        assert isinstance(down_resp, dict), f"move_priority_down 返回类型异常: {type(down_resp)}"
        assert 'data' in down_resp, f"move_priority_down 应包含 data: {down_resp}"
        down_data = down_resp['data']

        # 基本字段校验
        assert down_data.get('id') is not None, f"返回缺少 id: {down_data}"
        assert str(down_data.get('id')) == str(
            plan2_id), f"返回 id 应与请求 id 匹配: expect {plan2_id}, got {down_data.get('id')}"
        assert isinstance(down_data.get('priority'), int), f"priority 类型应为 int: {down_data}"
        assert down_data.get('priority') >= 0, f"priority 不应为负数: {down_data}"
        assert isinstance(down_data.get('dbModifyTime'), int), f"dbModifyTime 类型应为 int: {down_data}"
        assert down_data.get(
            'dbModifyTime') >= before_op_ts, f"dbModifyTime ({down_data.get('dbModifyTime')}) 应在操作时间之后 ({before_op_ts})"

        priority_after_down = down_data['priority']

        # 2) 再对第二条执行上移：返回字段校验，并且 priority 应小于下移后的值（优先级回升）
        before_up_ts = int(time.time() * 1000)
        up_resp = self.admin_study.move_priority_up(self.authorization, plan2_id)
        assert isinstance(up_resp, dict), f"move_priority_up 返回类型异常: {type(up_resp)}"
        assert 'data' in up_resp, f"move_priority_up 应包含 data: {up_resp}"
        up_data = up_resp['data']

        assert up_data.get('id') is not None, f"返回缺少 id: {up_data}"
        assert str(up_data.get('id')) == str(
            plan2_id), f"返回 id 应与请求 id 匹配: expect {plan2_id}, got {up_data.get('id')}"
        assert isinstance(up_data.get('priority'), int), f"priority 类型应为 int: {up_data}"
        assert isinstance(up_data.get('dbModifyTime'), int), f"dbModifyTime 类型应为 int: {up_data}"
        assert up_data.get(
            'dbModifyTime') >= before_up_ts, f"dbModifyTime ({up_data.get('dbModifyTime')}) 应在上移操作时间之后 ({before_up_ts})"

        priority_after_up = up_data['priority']

        # 核心数值关系断言：上移后应比下移后优先（数值更小）
        assert priority_after_up < priority_after_down, (
            f"上移后 priority ({priority_after_up}) 应小于下移后 ({priority_after_down})"
        )

        # 额外一致性断言：检查 plan1 在两个操作后仍然存在且未被误改（调用详情接口验证名称/id）
        detail1 = self.study_plan.studyPlan_details(self.authorization, plan1_id)
        assert isinstance(detail1, dict) and 'data' in detail1, f"getStudyPlanDetail 返回异常: {detail1}"
        detail1_data = detail1['data']
        assert detail1_data.get('id') == plan1_id or str(detail1_data.get('id')) == str(plan1_id)
        assert detail1_data.get('name') == '基础词汇学习计划', "plan1 名称异常或被修改"

        # 最后保证两个操作都有返回有效的 dbModifyTime 且它们不相等（表明确实有两次写操作）
        assert up_data['dbModifyTime'] != down_data['dbModifyTime'], "上移/下移的 dbModifyTime 不应相同"