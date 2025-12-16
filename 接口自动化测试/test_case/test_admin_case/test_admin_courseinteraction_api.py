import sys
import os

from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.admin.admin_courseinteraction_api import AdminCourseinteractionApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.admin
@pytest.mark.CourseInteraction
class TestAdminCourseInteraction:

    def setup_class(self):
        self.courseInteraction = AdminCourseinteractionApi()
        self.admincourse = AdminCourseApi()
        self.authorization = self.courseInteraction.get_authorization()
        self.admin_authorization = self.courseInteraction.get_admin_authorization()[0]

    @pytest.fixture(scope='class')
    def courselistAll(self):
        courselistAll = self.admincourse.course_listAll(self.admin_authorization, 638245113409605)
        yield courselistAll

    @pytest.mark.smoke
    def test_admin_courseinteraction_positive_getList_ok(self, courselistAll):
        """查询课程交互类型映射列表-正向用例"""
        courseId = courselistAll['data'][0]["id"]
        courseName = courselistAll['data'][0]["name"]
        pl = {
            "courseId": courseId,
            "courseName": courseName,
            "difficultyLevel": 'L1',
        }
        res = self.courseInteraction.course_interaction_list(self.admin_authorization, **pl)
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
    def test_admin_courseinteraction_permission_getList(self, desc, value):
        """查询课程交互类型映射列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.courseInteraction.course_interaction_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_admin_courseinteraction_scenario_getList_invalid_courseId(self):
        """查询课程交互类型映射列表-场景异常-无效的courseId"""
        courseId = 999999
        res = self.courseInteraction.course_interaction_list(self.admin_authorization, courseId=courseId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"