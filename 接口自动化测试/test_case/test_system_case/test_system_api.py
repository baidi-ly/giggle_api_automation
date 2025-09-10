import datetime
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

    @pytest.mark.pendingRelease
    def test_system_health_with_right_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.health(self.authorization, code=500)    # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_health_without_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.health(self.authorization, code=500)    # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["message"] == "Required request parameter 'token' for method parameter type String is not present"


    @pytest.mark.pendingRelease
    def test_system_health_with_wrong_token(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        health_res = self.sys.health(self.authorization, code=500)    # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["message"] == "Required request parameter 'token' for method parameter type String is not present"

    @pytest.mark.pendingRelease
    def test_system_health_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据

        health_res = self.sys.health('')    # TODO
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"

    @pytest.mark.pendingRelease
    def test_system_info_with_right_token(self):
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
    def test_system_info_with_wrong_token(self):
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
    def test_system_ping_with_wrong_token(self):
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