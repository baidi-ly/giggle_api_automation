#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
admin_skillrelation_api API接口
"""
import json

import requests
import time
from config import RunConfig
from test_case.page_api.base_api import BaseAPI

base_url = RunConfig.base_url


class AdminSkillrelationApi(BaseAPI):
    """技能关系相关接口类"""

    def importSkillRelation_ById(self, authorization, file=None, DeviceType="web", code=200, **kwargs):
        """
        根据ID导入技能关系
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-17
        url = f"https://{base_url}/admin/skill-relation/import-by-id"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, files=file)
        error_msg = "根据ID导入技能关系"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def importSkillRelation_ByName(self, authorization, file=None, DeviceType="web", code=200, **kwargs):
        """
        根据名称导入技能关系
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-17
        url = f"https://{base_url}/admin/skill-relation/import-by-name"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, files=file)
        error_msg = "根据名称导入技能关系"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

