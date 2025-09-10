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
            file_path = os.getcwd() + '../test_data/system_token.json'
            with open(file_path, 'r') as f:
                self.token = json.load(f)['token']
        except Exception as e:
            print(f"获取系统相关接口的指定token失败：{e}")

    @pytest.mark.pendingRelease
    def test_system_health_with_right_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.health(self.authorization, self.token)    # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_health_with_wrong_token(self):
        """有效的kidId，返回完整统计数据"""
        token = 'xEr0:v1f7@A]DYXg6WL_?JEUp/>yDHsdsdsd'
        # 获取孩子学习统计数据
        health_res = self.sys.health(self.authorization, token, code=500)    # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_health_without_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.health(self.authorization, '', code=500)    # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_health_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据

        health_res = self.sys.health('', self.token)    # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"

    @pytest.mark.pendingRelease
    def test_system_info_with_right_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.info(self.authorization)  # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"][
                   "message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_info_with_wrong_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.info(self.authorization, code=500)  # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"][
                   "message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_info_without_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.info(self.authorization, code=500)  # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"][
                   "message"] == "Required request parameter 'token' for method parameter type String is not present"
    @pytest.mark.pendingRelease
    def test_system_info_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据

        health_res = self.sys.info('')  # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"

    @pytest.mark.pendingRelease
    def test_system_ping_with_right_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.ping(self.authorization)  # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"][
                   "message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_ping_with_wrong_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.ping(self.authorization, code=500)  # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"][
                   "message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_ping_without_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.ping(self.authorization, code=500)  # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"][
                   "message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_ping_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据

        health_res = self.sys.ping('')  # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"

    @pytest.mark.pendingRelease
    def test_system_ping_with_wrong_ip(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据

        health_res = self.sys.ping('')  # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"