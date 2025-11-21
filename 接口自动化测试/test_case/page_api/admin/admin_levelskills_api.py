#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
admin_levelskills_api API接口
"""
import json
import time

import requests

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

base_url = RunConfig.admin_baseurl


class AdminLevelskillsApi(BaseAPI):
    """等级技能接口类"""

    def createLevelSkill(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        新增等级技能
        :param learningLevel: (object, string, required) 学习等级
        :param educationType: (object, string, required) 教育类型
        :param skill: (object, string, required) 技能名称
        :param necessary: (object, string, required) 是否必修
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-10
        url = f"https://{base_url}/admin/level-skills"
        payload = {
            "learningLevel": "L1",
            "educationType": "Early Years",
            "skill": "Reading-Level1",
            "necessary": True
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新增等级技能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def level_skills(self, authorization, page=0, size=1000, skill='', DeviceType="web", code=200, **kwargs):
        """
        分页查询课程等级技能列表
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param skill: (string, query, optional) 技能名称搜索
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-10
        url = f"https://{base_url}/admin/level-skills/list"
        payload = {
            "page": page,
            "size": size,
            "skill": skill  # Reading\Level1\Writing
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "分页查询课程等级技能列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateLevelSkills(self, authorization, skill_id, DeviceType="web", code=200, **kwargs):
        """
        更新等级技能
        :param ids: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-10
        url = f"https://{base_url}/admin/level-skills/{skill_id}"
        payload = {
            "educationType": "string",
            "necessary": True,
            "prerequisiteSkill": None,
            "parentSkill": None
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新等级技能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteLevelskills(self, authorization, ids:list, DeviceType="web", code=200, **kwargs):
        """
        批量删除等级技能
        :param ids: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-10
        url = f"https://{base_url}/admin/level-skills/batch-delete"
        payload = {
            "ids": ids
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers, json=payload)
        error_msg = "批量删除等级技能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def levelSkills_import(self, authorization, file=None, DeviceType="web", code=200, **kwargs):
        """
        批量导入学习技能
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-10
        url = f"https://{base_url}/admin/level-skills/import"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, files=file)
        error_msg = "批量导入学习技能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False