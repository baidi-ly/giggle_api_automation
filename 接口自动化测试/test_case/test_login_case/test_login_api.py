import datetime
import sys
import os

from test_case.page_api.base_api import BaseAPI
from test_case.page_api.init.init_api import InitAPI

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.login
class TestLogin:

    def setup_class(self):
        self.base = BaseAPI()
        self.init_api = InitAPI()


    def teardown_class(self):
        '''
        所有用例执行完之后执行，可执行动作，清理所有注册的数据
        本次测试mock只创建了注册接口，未创建清除注册用户接口，暂无代码
        '''
        pass

    @pytest.fixture(scope="class", autouse=False)
    def reister_fixtrue(self):
        # 前置条件-账号已注册
        username = "baidi"
        email = "bd22434@163.com"
        password = "bb22434"
        verifyCode = "123456"
        inviteByCode = ""
        sign_up_res = self.init_api.register(username, email, password, verifyCode, inviteByCode)
        assert sign_up_res["message"] == "注册成功"
        yield email, password

    def test_AA_user_login_email(self):
        """正常登录"""
        # 1. 注册新账号
        email = "di.bbb@giggleacademy.me"
        password = "Bd2243422434~"
        login_res = self.base.login(email, password)
        assert login_res["message"] == "success"

    def test_AD_user_loginByEmail(self):
        """登录失败 (提供无效的邮箱格式（如缺少“@”）)"""
        pass

    def test_AD_user_loginByPhonePassword(self):
        """登录失败 (提供无效的邮箱格式（如缺少“@”）)"""
        pass

    def test_AD_user_loginByPhone(self):
        """登录失败 (提供无效的邮箱格式（如缺少“@”）)"""
        pass

    def test_AD_user_loginByWechat(self):
        """登录失败 (提供错误的密码)"""
        pass

    def test_AD_user_loginByGoogle(self):
        """登录失败 (提供空的邮箱字段)"""
        idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJkN2VkMzM4YzBmMTQ1N2IyMTRhMjc0YjVlMGU2NjdiNDRhNDJkZGUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1OTYzOTIzNDE5OTMtaGlkNWtjc3Jnb24yOGpwOGZpcDk4bmczanA5OGluN2QuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1OTYzOTIzNDE5OTMtaGlkNWtjc3Jnb24yOGpwOGZpcDk4bmczanA5OGluN2QuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDk1OTkzNjkxMjcyODE4MzY0MTciLCJoZCI6ImdpZ2dsZWFjYWRlbXkubWUiLCJlbWFpbCI6ImRpLmJiYkBnaWdnbGVhY2FkZW15Lm1lIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoibnVsbCIsIm5iZiI6MTc1Njk2Mzg0NCwibmFtZSI6IkRpIEJvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0l0ZFU3d2YyMUFwbkJlU1c2Wmh0S0FwUkNqd2F1aG5HTnhVVGtTZ1lnYUh3dWMyUT1zOTYtYyIsImdpdmVuX25hbWUiOiJEaSIsImZhbWlseV9uYW1lIjoiQm8iLCJpYXQiOjE3NTY5NjQxNDQsImV4cCI6MTc1Njk2Nzc0NCwianRpIjoiZTQyNWJlZmJlMjMxNTNhMmI1NzNlY2VmYmI0ZmZjZTc4MTlhMjg5NCJ9.gxkFmKbfyy53gpd8I9dq7_1gz1PyG-cNebczmOYt2JfpHIp0vR52P38WrzuCTO5MsxFCf7uOU4T2LHDIAeWF5QKea4Zhsl0_guOdgyo7BzOEROKs_TeGHcYngfQqBlha6ZEq1ZtTl8Dts5VAJwTnSH1hQLRpexuamqbrxZbucDTGQvnAmgAb9ophmVjN0acC4wgMnI7hS1bTjkpIi6vAbUSqL_0xmHLotoWivdQfhCHJNilCRKWFeA-XgJj4WFS0kbozITdYQgfXm8wGLRo5qE8q94dxQdlijZNwQMuVblt5mgcj4Ndg368kfpaYsGlFVj4EH1xCk9GKfLpToEt0ig"
        login_res = self.base.loginByGoogle(idToken)
        assert login_res["message"] == "success"

    def test_AD_user_loginByApple(self):
        """登录失败 (提供错误的密码)"""
        pass
