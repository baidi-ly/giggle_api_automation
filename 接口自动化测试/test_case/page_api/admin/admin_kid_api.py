#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
admin_kid_api API接口
"""
import json

import requests
import time
from config import RunConfig
from test_case.page_api.base_api import BaseAPI

base_url = RunConfig.admin_baseurl


class AdminKidApi(BaseAPI):
    """admin站点孩子相关接口"""

    def getInteractionPreference(self, authorization, kidId, topN=5, DeviceType="web", code=200):
        """
        查询孩子互动偏好
        :param kidId: (integer, path, required) kidId
        :param topN: (integer, query, optional) topN
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/kid/{kidId}/interaction-preference"
        payload = {
            "topN": topN
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询孩子互动偏好"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getSkillMastery(self, authorization, kidId, DeviceType="web", code=200):
        """
        获取学生技能掌握程度
        :param kidId: (integer, path, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/kid/{kidId}/skill-mastery"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取学生技能掌握程度"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getKidTags(self, authorization, kidId=0, DeviceType="web", code=200):
        """
        获取用户标签
        :param kidId: (integer, path, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/kid/{kidId}/tags"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取用户标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateKidTags(self, authorization, kidId, childAge=7, learningLevel='L1', DeviceType="web", code=200, **kwargs):
        """
        更新用户标签
        :param kidId: (integer, path, required) kidId
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/kid/{kidId}/tags/update"
        payload = {
            "childAge": childAge,
            "learningLevel": learningLevel
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新用户标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateSkillMastery(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        更新用户技能标签
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-21
        url = f"https://{base_url}/admin/kid/skill-mastery/update"
        payload = {
            "kidId": 0,
            "skill": "string",
            "masteryScore": 0,
            "masteryState": "string",
            "componentExposureRate": 0
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新用户技能标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def tagChangeLogs(self, authorization, kidId, operator='', DeviceType="web", code=200, **kwargs):
        """
        获取孩子等级状态操作日志
        :param changeItem: (string, query, optional) 孩子学习状态更改项
        :param endTime: (string, query, optional) 截止时间
        :param kidId: (integer, query, optional) kidId
        :param operator: (string, query, optional) 操作者
        :param operatorSource: (string, query, optional) 操作来源
        :param page: (integer, query, optional) page
        :param pageSize: (integer, query, optional) pageSize
        :param startTime: (string, query, optional) 开始时间
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-08
        url = f"https://{base_url}/admin/kid/tag-change-log/list"
        payload = {
            "changeItem": '',
            "endTime": '',
            "kidId": kidId,
            "operator": operator,
            "operatorSource": '',
            "page": 0,
            "pageSize": 10,
            "startTime": ''
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取孩子等级状态操作日志"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

