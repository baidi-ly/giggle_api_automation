import random
import sys
import os
from time import strftime

from test_case.page_api.admin.admin_flashcards_api import AdminFlashcardsApi
from test_case.page_api.admin.admin_studyplan_api import AdminStudyplanApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminStudyPlan
class TestAdminStudyPlan:

    def setup_class(self):
        self.admin_study = AdminStudyplanApi()
        self.admin_flashcard = AdminFlashcardsApi()
        self.authorization = self.admin_study.get_admin_authorization()
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

    def teardown_class(self):
        studyPlans_res = self.admin_study.study_plan_list(self.authorization, category='vocabulary', status=1)['data']['content']
        for studyPlan in studyPlans_res:
            if '基础词汇学习计划' in studyPlan["name"]:
                try:
                    res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlan["id"])
                    assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
                    assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
                except Exception as e:
                    print(e)

    @pytest.fixture(scope="class")
    def create_flashcards(self):
        name = 'create_flashcards' + self.now + str(random.randint(1, 10))
        quiz_res = self.admin_flashcard.flashcards_create(self.authorization, name=name)["data"]
        contents = [
            {
                "contentId": quiz_res["id"],
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
        yield contents
        self.admin_flashcard.delete_flashcards(self.authorization, quiz_res["id"])

    @pytest.mark.release
    def test_admin_studyplan_positive_create_ok(self, create_flashcards):
        """创建学习计划（包含单元和内容）-正向用例"""
        contents = create_flashcards
        res = self.admin_study.study_plan_create(self.authorization, contents)
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
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_studyplan_permission_create(self, desc, value):
        """创建学习计划（包含单元和内容）-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_study.study_plan_create(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_studyplan_positive_delete_studyPlan_ok(self, create_flashcards):
        """删除学习计划包-正向用例"""
        contents = create_flashcards
        studyPlanId = self.admin_study.study_plan_create(self.authorization, contents)["data"]["id"]
        res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlanId)
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
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_studyplan_permission_delete_studyPlan(self, desc, value):
        """删除学习计划包-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_study.delete_studyPlan(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 200),
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_admin_studyplan_boundary_delete_studyPlan_studyPlanId(self, desc, value, code):
        """删除学习计划包-边界值测试(studyPlanId)"""
        res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100150, f"接口返回状态码异常: 预期【100150】，实际【{res['code']}】"
        assert res['message'] == 'Study plan not found', f"接口返回message信息异常: 预期【'Study plan not found'】，实际【{res['message']}】"
        assert res['data'] == 'Study plan not found', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_studyplan_scenario_delete_studyPlan_invalid_studyPlanId(self):
        """删除学习计划包-场景异常-无效的studyPlanId"""
        studyPlanId = 999999999
        res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlanId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100150, f"接口返回状态码异常: 预期【100150】，实际【{res['code']}】"
        assert res['message'] == 'Study plan not found', f"接口返回message信息异常: 预期【'Study plan not found'】，实际【{res['message']}】"
        assert res['data'] == 'Study plan not found', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_studyplan_positive_study_plan_list_ok(self):
        """学习计划列表-正向用例"""
        res = self.admin_study.study_plan_list(self.authorization)
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
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_studyplan_permission_study_plan_list(self, desc, value):
        """学习计划列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_study.study_plan_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_studyplan_positive_putUpdate_ok(self):
        """更新学习计划-正向用例"""
        studyPlans_res = self.admin_study.study_plan_list(self.authorization, category='vocabulary')
        content = studyPlans_res['data']['content'][:2]
        studyPlans_res['data']['content'] = content
        res = self.admin_study.update_study_plan(self.authorization, studyPlanId=self.studyPlanId, **studyPlans_res['data'])
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
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_studyplan_permission_putUpdate(self, desc, value):
        """更新学习计划-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_study.update_study_plan(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_studyplan_positive_putStatus_ok(self):
        """学习计划状态变更-正向用例"""
        res = self.admin_study.putStatus(self.authorization, studyPlanId=self.studyPlanId)
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
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_studyplan_permission_putStatus(self, desc, value):
        """学习计划状态变更-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_study.putStatus(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 400),
            ('zero', 0, 200),
            ('one', 1, 200),
            ('two', 2, 400),
            ('max', 2147483647, 400),
        ]
    )
    def test_admin_studyplan_boundary_putStatus_studyPlanId(self, desc, value, code):
        """学习计划状态变更-边界值测试(studyPlanId)"""
        res = self.admin_study.putStatus(self.authorization, self.studyPlanId, value, code=code)
        if code == 200:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
        else:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'] == {'status': 'Status must be 0 or 1'}, f"接口返回data数据异常：{res['data']}"
