import datetime
from time import strftime

import pytest
import sys
import os

from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.user.user_api import UserApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.User
class TestUser:

    def setup_class(self):
        self.user = UserApi()
        self.authorization = self.user.get_authorization()
        self.course = CourseApi()

        self.now = strftime("%Y%m%d%H%M%S")


    @pytest.fixture(scope="class")
    def get_userIds(self):
        '''方法前置 - 创建kidId'''
        # 创建小孩账户
        couerseList = self.course.listAllWithLevel(self.authorization)["data"]
        yield couerseList

    @pytest.mark.pendingRelease
    def test_user_videoWhitelist_update_normal(self, get_userIds):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        userIds = get_userIds
        event_res = self.user.update_videoWhitelist(self.authorization, userIds)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_user_videoWhitelist_update_empty(self, get_userIds):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        userIds = []
        event_res = self.user.update_videoWhitelist(self.authorization, userIds)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_user_videoWhitelist_update_wrong(self, get_userIds):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        userIds = [111, -9999, "~!@#", "", ()]
        event_res = self.user.update_videoWhitelist(self.authorization, userIds)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"
