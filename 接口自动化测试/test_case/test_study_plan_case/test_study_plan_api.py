from time import strftime

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

        name = 'create_flashcards' + self.now
        quiz_res = self.admin_flashcard.flashcards_create(self.authorization, name=name)["data"]
        self.contentId = quiz_res["id"]
        contents = [
            {
                "contentId": self.contentId,
                "contentType": "flash_card",
                "difficulty": "easy",
                "name": "基础词汇测验",
                "sortOrder": 1,
                "wordCount": 20,
                "contentConfig": {
                    "words": ["apple", "banana", "cat", "dog"]
                }
            }
        ]
        self.studyPlanId = self.admin_study.study_plan_create(self.authorization, contents)["data"]["id"]
        res = self.admin_study.putStatus(self.authorization, studyPlanId=self.studyPlanId)
        assert res
        # 获取kidId
        self.kidId = self.kid.getKids(self.authorization)["data"][0]["id"]

    def teardown_class(self):
        studyPlans_res0 = self.admin_study.study_plan_list(self.authorization, category='vocabulary', status=0)['data']['content']
        studyPlans_res1 = self.admin_study.study_plan_list(self.authorization, category='vocabulary', status=1)['data']['content']
        for studyPlan in studyPlans_res0:
            if '基础词汇学习计划' in studyPlan["name"]:
                try:
                    res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlan["id"])
                    assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
                    assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
                except Exception as e:
                    print(e)
        for studyPlan in studyPlans_res1:
            if '基础词汇学习计划' in studyPlan["name"]:
                try:
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
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
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
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
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
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
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

    # @pytest.mark.smoke
    # def test_study_plan_positive_complete_ok(self):
    #     """完成学习计划内容-正向用例"""
    #     unitId = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, self.kidId)['data'][0]['id']
    #     studyPlanContentId = self.study_plan.study_plan_contents(self.authorization, unitId, self.kidId)['data'][0]['id']
    #     pl = {
    #         "completionTime": "2025-10-21T08:36:11.811Z",
    #         "kidId": self.kidId,
    #         "learningDuration": 0,
    #         "studyPlanContentId": studyPlanContentId,
    #         "studyPlanId": self.studyPlanId,
    #         "studyPlanUnitId": unitId
    #     }
    #     res = self.study_plan.studyplan_content_complete(self.authorization, **pl)
    #     assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
    #     assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
    #     assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
    #     assert res['data'], f"接口返回data数据异常：{res['data']}"

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
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.study_plan.studyplan_content_complete(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_study_positive_claimReward_ok(self):
        """领取学习计划奖励-正向用例"""
        unitId = self.study_plan.study_plan_units(self.authorization, self.studyPlanId, self.kidId)['data'][0]['id']
        studyPlanContentId = self.study_plan.study_plan_contents(self.authorization, unitId, self.kidId)['data'][0]['id']
        pl = {
            "completionTime": "2025-10-21T08:36:11.811Z",
            "kidId": self.kidId,
            "learningDuration": 0,
            "studyPlanContentId": studyPlanContentId,
            "studyPlanId": self.studyPlanId,
            "studyPlanUnitId": unitId
        }
        self.study_plan.studyplan_content_complete(self.authorization, **pl)
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
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
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