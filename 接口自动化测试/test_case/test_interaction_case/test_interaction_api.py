import datetime
from time import strftime

import pytest
import sys
import os

from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.interaction.interaction import InteractionApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.Interaction
class TestInteraction:

    def setup_class(self):
        self.interaction = InteractionApi()
        self.authorization = self.interaction.get_authorization()
        self.course = CourseApi()
        self.now = strftime("%Y%m%d%H%M%S")


    @pytest.fixture(scope="class")
    def get_couerseList(self):
        '''方法前置 - 创建kidId'''
        # 创建小孩账户
        couerseList = self.course.listAllWithLevel(self.authorization)["data"]
        yield couerseList

    @pytest.mark.pendingRelease
    def test_interaction_event_single(self, get_couerseList):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        couerseList = get_couerseList[0]['courseList']
        eventName = "交互事件" + self.now
        courses = [
            {
                "eventName": eventName,
                "params": {
                    "courseId": couerseList[0]["id"],
                    "lessonType": "normal"
                }
             }
        ]
        # 获取孩子学习统计数据
        event_res = self.interaction.event(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_interaction_event_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        courses = []
        # 获取孩子学习统计数据
        event_res = self.interaction.event(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_interaction_event_multi(self, get_couerseList):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        couerseList = get_couerseList[0]['courseList']
        courses = []
        for i in range(len(couerseList)):
            eventName = "交互事件" + self.now
            courses.append({"eventName": eventName,
            "params": {
                "courseId": couerseList[i]["id"],
                "lessonType": "normal"
            }})
        # 获取孩子学习统计数据

        event_res = self.interaction.event(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_interaction_event_course_not_exist(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        eventName = "交互事件" + self.now
        courses = [
            {
                "eventName": eventName,
                "params": {
                    "courseId": 9999999999,
                    "lessonType": "normal"
                }
             }
        ]
        # 获取孩子学习统计数据
        event_res = self.interaction.event(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_interaction_event_name_empty(self, get_couerseList):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        couerseList = get_couerseList[0]['courseList']
        courses = [
            {
                "eventName": '',
                "params": {
                    "courseId": couerseList[0]["id"],
                    "lessonType": "normal"
                }
             }
        ]
        # 获取孩子学习统计数据
        event_res = self.interaction.event(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'invalid parameter'
        assert event_res["data"] == 'invalid parameter'

    @pytest.mark.pendingRelease
    def test_interaction_event_name_wrong(self, get_couerseList):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        couerseList = get_couerseList[0]['courseList']
        courses = [
            {
                "eventName": True,
                "params": {
                    "courseId": couerseList[0]["id"],
                    "lessonType": "normal"
                }
             }
        ]
        # 获取孩子学习统计数据
        event_res = self.interaction.event(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'invalid parameter'
        assert event_res["data"] == 'invalid parameter'