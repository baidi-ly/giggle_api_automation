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

    @pytest.fixture(scope="class")
    def create_flashcards(self):
        name = 'create_flashcards' + self.now
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
                    "words": ["apple", "banana", "cat"]
                }
            }
        ]

        yield contents

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