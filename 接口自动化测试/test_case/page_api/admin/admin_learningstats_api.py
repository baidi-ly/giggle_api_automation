#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
admin_learningstats_api API接口
"""

import requests
import time
from config import RunConfig

base_url = RunConfig.base_url


class AdminLearningstatsApi:
    """API接口类"""
    
    def __init__(self):
        self.base_url = base_url
    
    def request_header(self, timestamp, authorization, DeviceType="web"):
        """构建请求头"""
        return {
            "Authorization": authorization,
            "DeviceType": DeviceType,
            "timestamp": timestamp,
            "Content-Type": "application/json"
        }
