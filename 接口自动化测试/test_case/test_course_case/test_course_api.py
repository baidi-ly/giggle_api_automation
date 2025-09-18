import datetime

import pytest
import sys
import os

from test_case.page_api.course.course_api import CourseApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.Course
class TestCourse:

    def setup_class(self):
        self.course = CourseApi()
        self.authorization = self.course.get_authorization()

    @pytest.mark.release
    def test_course_blockedCourseIds_login(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        stats_res = self.course.blockedCourseIds(self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["blockedIds"]

    @pytest.mark.release
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
