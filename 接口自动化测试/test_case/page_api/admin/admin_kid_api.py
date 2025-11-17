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
        # Create Data:  V1.19.0  &  2025-11-17
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

    def getSkillMastery(self, authorization, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        获取学生技能掌握程度
        :param kidId: (integer, path, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-17
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

