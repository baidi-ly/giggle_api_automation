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
        email = "bd22434@163.com"
        password = "Bd2243422434~"
        login_res = self.base.login(email, password)
        assert login_res["message"] == "success"

    def test_user_login_email_has_bindAccount(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        email = "bd22434@163.com"
        password = "Bd2243422434~"
        bindAccount = "82396147535823"
        login_res = self.base.login(email, password, bindAccount)
        assert "data" in login_res, f"获取孩子学习统计数据接口没有data数据，response->{login_res}"
        assert login_res["message"] == "success"

    @pytest.mark.parametrize("bindAccount", [123, 123.4, True, "!@#~"], ids=["integer", "float", "boolen", "special characters"])
    def test_user_login_email_has_not_bindAccount(self, bindAccount):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        email = "bd22434@163.com"
        password = "Bd2243422434~"
        login_res = self.base.login(email, password, bindAccount)
        assert "data" in login_res, f"获取孩子学习统计数据接口没有data数据，response->{login_res}"
        assert login_res["message"] == "success"

