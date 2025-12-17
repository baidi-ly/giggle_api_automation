#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
admin_gametemplate_api API接口
"""

import requests
import time
from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminGametemplateApi(BaseAPI):
    """admin后台游戏接口类"""
    
    def game_template_list(self, authorization, DeviceType="web"):
        """
        获取游戏列表
        :param request:
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-17
        url = f"https://{base_url}/admin/game-template/list"
        payload = {
            'status': 1,
            'page': 0,
            'pageSize': 100,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取游戏列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response