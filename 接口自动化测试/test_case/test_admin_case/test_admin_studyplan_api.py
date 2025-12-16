import random
import sys
import os
from time import strftime

from test_case.page_api.admin.admin_flashcards_api import AdminFlashcardsApi
from test_case.page_api.admin.admin_studyplan_api import AdminStudyplanApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.admin
@pytest.mark.adminStudyPlan
class TestAdminStudyPlan:

    def setup_class(self):
        self.admin_study = AdminStudyplanApi()
        self.admin_flashcard = AdminFlashcardsApi()
        self.authorization = self.admin_study.get_admin_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

        try:
            # 新增闪卡
            name = 'dibo_test_flashcards' + self.now
            quiz_res = self.admin_flashcard.flashcards_create(self.authorization, name=name)["data"]
            self.contentId = quiz_res["id"]
            # 创建学习计划（包含单元和内容）
            study_plan_name = "dibo_test_studyPlan" + self.now
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
            # 开启创建学习计划（包含单元和内容）
            res = self.admin_study.putStatus(self.authorization, self.studyPlanId, 1)
            assert res['data']['status'] == 1, "开启创建学习计划失败！"
        except Exception as e:
            print(f'新增闪卡失败，原因是：{e}')

    def teardown_class(self):
        # 查询状态为关闭的学习计划列表
        studyPlans_res0 = self.admin_study.study_plan_list(self.authorization, category='vocabulary', status=0)['data']['content']
        # 查询状态为开启的学习计划列表
        studyPlans_res1 = self.admin_study.study_plan_list(self.authorization, category='vocabulary', status=1)['data']['content']
        for studyPlan in studyPlans_res0:
            if '基础词汇学习计划' in studyPlan["name"] or studyPlan["name"].startswith('dibo_test'):
                try:
                    # 删除学习计划包
                    res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlan["id"])
                    assert res['code'] == 200
                except Exception as e:
                    print(f"删除学习计划包失败，原因是：{e}")
        for studyPlan in studyPlans_res1:
            if '基础词汇学习计划' in studyPlan["name"] or studyPlan["name"].startswith('dibo_test'):
                try:
                    # 删除学习计划包
                    res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlan["id"])
                    assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
                    assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
                except Exception as e:
                    print(f"删除学习计划包失败，原因是：{e}")

        # 删除测试闪卡
        list_res = self.admin_flashcard.flashcards_list(self.authorization)
        for flashcard in list_res['data']:
            if flashcard['name'].starswith('dibo_test'):
                quiz_id = flashcard["id"]
                delete_res = self.admin_flashcard.delete_flashcards(self.authorization, quiz_id)
                assert delete_res['message'] == 'success'

    @pytest.fixture(scope="class")
    def create_flashcards(self):
        name = 'dibo_test_flashcards' + self.now + str(random.randint(1, 10))
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

    @pytest.mark.smoke
    def test_admin_studyplan_positive_create_ok(self, create_flashcards):
        """创建学习计划（包含单元和内容）-正向用例"""
        contents = create_flashcards
        res = self.admin_study.study_plan_create(self.authorization, contents)
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
    def test_admin_studyplan_permission_create(self, desc, value):
        """创建学习计划（包含单元和内容）-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_study.study_plan_create(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_studyplan_positive_delete_studyPlan_ok(self, create_flashcards):
        """删除学习计划包-正向用例"""
        contents = create_flashcards
        studyPlanId = self.admin_study.study_plan_create(self.authorization, contents)["data"]["id"]
        res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlanId)
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
    def test_admin_studyplan_permission_delete_studyPlan(self, desc, value):
        """删除学习计划包-权限测试"""
        res = self.admin_study.delete_studyPlan(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

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

    def test_admin_studyplan_scenario_delete_studyPlan_invalid_studyPlanId(self):
        """删除学习计划包-场景异常-无效的studyPlanId"""
        studyPlanId = 999999999
        res = self.admin_study.delete_studyPlan(self.authorization, studyPlanId=studyPlanId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100150, f"接口返回状态码异常: 预期【100150】，实际【{res['code']}】"
        assert res['message'] == 'Study plan not found', f"接口返回message信息异常: 预期【'Study plan not found'】，实际【{res['message']}】"
        assert res['data'] == 'Study plan not found', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_studyplan_positive_study_plan_list_ok(self):
        """学习计划列表-正向用例"""
        res = self.admin_study.study_plan_list(self.authorization)
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
    def test_admin_studyplan_permission_study_plan_list(self, desc, value):
        """学习计划列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_study.study_plan_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_studyplan_positive_putUpdate_ok(self):
        """更新学习计划-正向用例"""
        studyPlans_res = self.admin_study.study_plan_list(self.authorization, category='vocabulary')
        content = studyPlans_res['data']['content'][:2]
        studyPlans_res['data']['content'] = content
        res = self.admin_study.update_study_plan(self.authorization, studyPlanId=self.studyPlanId, **studyPlans_res['data'])
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100151, f"接口返回状态码异常: 预期【100151】，实际【{res['code']}】"
        assert res['message'] == 'Study plan content type not supported', f"接口返回message信息异常: 预期【Study plan content type not supported】，实际【{res['message']}】"
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
    def test_admin_studyplan_permission_putUpdate(self, desc, value):
        """更新学习计划-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_study.update_study_plan(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_studyplan_positive_putStatus_ok(self):
        """学习计划状态变更-正向用例"""
        res = self.admin_study.putStatus(self.authorization, studyPlanId=self.studyPlanId)
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
    def test_admin_studyplan_permission_putStatus(self, desc, value):
        """学习计划状态变更-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_study.putStatus(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

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
