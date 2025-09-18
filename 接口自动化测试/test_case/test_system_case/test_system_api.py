import datetime
import json
import sys
import os
from time import strftime

from test_case.page_api.system.system_api import SystemApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.System
class TestSystem:

    def setup_class(self):
        self.sys = SystemApi()
        self.authorization = self.sys.get_authorization()
        self.now = strftime("%Y%m%d%H%M%S")

        try:
            # 获取系统相关接口的指定token
            file_path = os.getcwd() + '/test_data/system_token.json'
            with open(file_path, 'r') as f:
                self.token = json.load(f)['token']
        except Exception as e:
            print(f"获取系统相关接口的指定token失败：{e}")

    @pytest.mark.release
    def test_system_health_login(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.health(self.authorization, self.token)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["isUp"]
        assert health_res["data"]["status"] == "UP"

    @pytest.mark.release
    def test_system_health_customer(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.health(self.token)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["isUp"]
        assert health_res["data"]["status"] == "UP"

    @pytest.mark.release
    def test_system_health_with_wrong_token(self):
        """有效的kidId，返回完整统计数据"""
        token = 'xEr0:v1f7@A]DYXg6WL_?JEUp/>yDHsdsdsd'
        # 获取孩子学习统计数据
        health_res = self.sys.health(token, code=403)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["message"] == 'permission not allowed'

    @pytest.mark.release
    def test_system_health_without_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.health('', code=403)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["message"] == 'permission not allowed'

    @pytest.mark.release
    def test_system_info_login(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.info(self.authorization, self.token)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["git"]
        assert health_res["data"]["build"]['name'] == 'Giggle-Server'

    @pytest.mark.release
    def test_system_info_customer(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.info(self.authorization, self.token)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["git"]
        assert health_res["data"]["build"]['name'] == 'Giggle-Server'

    @pytest.mark.release
    def test_system_info_with_wrong_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        token = 'xEr0:v1f7@A]DYXg6WL_?JEUp/>yDHsdsdsd'
        health_res = self.sys.info(token, code=403)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["message"] == 'permission not allowed'

    @pytest.mark.release
    def test_system_info_without_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.info('', code=403)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["message"] == 'permission not allowed'


    @pytest.mark.release
    def test_system_ping_with_login(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        ping_res = self.sys.ping(self.authorization, self.token)
        assert ping_res["data"]["message"] == 'pong'
        assert ping_res["data"]["server"] == "giggle-academy-server"

    @pytest.mark.release
    def test_system_ping_with_customer(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        ping_res = self.sys.ping(self.authorization, self.token)
        assert ping_res["data"]["message"] == 'pong'
        assert ping_res["data"]["server"] == "giggle-academy-server"

    @pytest.mark.release
    def test_system_ping_with_wrong_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        token = 'xEr0:v1f7@A]DYXg6WL_?JEUp/>yDHsdsdsd'
        health_res = self.sys.ping(token, code=403)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["message"] == 'permission not allowed'

    @pytest.mark.release
    def test_system_ping_without_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.ping('', code=403)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["message"] == 'permission not allowed'

