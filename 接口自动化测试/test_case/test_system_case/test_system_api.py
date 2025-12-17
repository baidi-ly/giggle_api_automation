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
        self.authorization, self.user_id = self.sys.get_authorization()
        self.now = strftime("%Y%m%d%H%M%S")

        try:
            # 获取系统相关接口的指定token
            file_path = os.getcwd() + '/test_data/system_token.json'
            with open(file_path, 'r') as f:
                self.token = json.load(f)['token']
        except Exception as e:
            print(f"获取系统相关接口的指定token失败：{e}")

    @pytest.mark.smoke
    def test_system_health_login(self):
        """系统健康状态检查"""
        # 系统健康状态检查
        health_res = self.sys.health(self.authorization, self.token)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["data"]["isUp"]
        assert health_res["data"]["status"] == "UP"

    @pytest.mark.smoke
    def test_system_health_customer(self):
        """系统健康状态检查"""
        # 系统信息检查
        health_res = self.sys.health(self.token)
        assert health_res["data"]["isUp"]
        assert health_res["data"]["status"] == "UP"

    def test_system_health_with_wrong_token(self):
        """系统健康状态检查"""
        token = 'xEr0:v1f7@A]DYXg6WL_?JEUp/>yDHsdsdsd'
        # 获取孩子学习统计数据
        health_res = self.sys.health(token, code=403)
        assert health_res["message"] == 'permission not allowed'

    def test_system_health_without_token(self):
        """系统健康状态检查"""
        # 系统信息检查
        health_res = self.sys.health('', code=403)
        assert health_res["message"] == 'permission not allowed'

    @pytest.mark.smoke
    def test_system_info_login(self):
        """系统健康状态检查"""
        # 系统信息检查
        health_res = self.sys.system_info(self.authorization, self.token)
        assert health_res["data"]["git"]
        assert health_res["data"]["build"]['name'] == 'Giggle-Server'

    @pytest.mark.smoke
    def test_system_info_customer(self):
        """系统健康状态检查"""
        # 系统信息检查
        health_res = self.sys.system_info(self.authorization, self.token)
        assert health_res["data"]["git"]
        assert health_res["data"]["build"]['name'] == 'Giggle-Server'

    def test_system_info_with_wrong_token(self):
        """系统信息检查"""
        # 系统信息检查
        token = 'xEr0:v1f7@A]DYXg6WL_?JEUp/>yDHsdsdsd'
        health_res = self.sys.system_info(token, code=403)
        assert health_res["message"] == 'permission not allowed'

    def test_system_info_without_token(self):
        """系统信息检查"""
        # 系统信息检查
        health_res = self.sys.system_info('', code=403)
        assert health_res["message"] == 'permission not allowed'

    @pytest.mark.smoke
    def test_system_system_ping_with_login(self):
        """简单的ping检查"""
        # 简单的ping检查
        ping_res = self.sys.system_ping(self.authorization, self.token)
        assert ping_res["data"]["message"] == 'pong'
        assert ping_res["data"]["server"] == "giggle-academy-server"

    @pytest.mark.smoke
    def test_system_system_ping_with_customer(self):
        """简单的ping检查"""
        # 简单的ping检查
        ping_res = self.sys.system_ping(self.authorization, self.token)
        assert ping_res["data"]["message"] == 'pong'
        assert ping_res["data"]["server"] == "giggle-academy-server"

    def test_system_ping_with_wrong_token(self):
        """简单的ping检查"""
        # 简单的ping检查
        token = 'xEr0:v1f7@A]DYXg6WL_?JEUp/>yDHsdsdsd'
        health_res = self.sys.system_ping(token, code=403)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["message"] == 'permission not allowed'

    def test_system_ping_without_token(self):
        """简单的ping检查"""
        # 简单的ping检查
        health_res = self.sys.system_ping('', code=403)
        assert "data" in health_res, f"获取孩子学习统计数据接口没有data数据，response->{health_res}"
        assert health_res["message"] == 'permission not allowed'

    @pytest.mark.smoke
    def test_system_positive_getMetadata_ok(self):
        """获取系统基础信息-正向用例"""
        # 获取系统基础信息
        res = self.sys.getMetadata(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_system_permission_getMetadata(self, desc, value):
        """获取系统基础信息-权限测试"""
        res = self.sys.getMetadata(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize('channel', ['ios', 'android', 'googleplay', 'appstore'])
    def test_system_positive_feature_toggle_ok(self, channel):
        """检查某个功能对用户是否开启（AB 测试开关)-正向用例"""
        res = self.sys.feature_toggle(self.authorization, self.user_id, key="storybook_new_ui", channel=channel)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['data']['userId'] == self.user_id
        assert res['data']['channel'] == channel
        assert res['data']['enabled'] == False