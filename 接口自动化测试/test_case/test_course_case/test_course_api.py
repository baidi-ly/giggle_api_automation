import datetime

import pytest
import sys
import os

from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.school.school_api import SchoolApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.Course
class TestCourse:

    def setup_class(self):
        self.course = CourseApi()
        self.school = SchoolApi()
        self.kid = KidApi()
        self.authorization = self.course.get_authorization()[0]

    def test_course_blockedCourseIds_login(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        stats_res = self.course.blockedCourseIds(self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["blockedIds"]

    def test_course_blockedCourseIds_customer(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        stats_res = self.course.blockedCourseIds('')
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["blockedIds"]

    def test_noargs_detail_basic(self):
        """获取所有课程分级列表"""
        res = self.api.detail(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_course_positive_recommendation_ok(self):
        """获取课程推荐-正向用例"""
        course_id = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
        kid_id = self.kid.getKids(self.authorization)["data"][0]['id']
        pl = {
            "currentCourseId": course_id,
            "includeReasonInfo": False,
            "kidId": kid_id,
            "recommendCount": 2
        }
        res = self.course.recommendation(self.authorization, **pl)
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
    def test_course_permission_recommendation(self, desc, value):
        """获取课程推荐-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.course.recommendation(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"