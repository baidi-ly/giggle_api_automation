import datetime
from time import strftime

import pytest
import sys
import os

from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.user.user_api import UserApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.User
class TestUser:

    def setup_class(self):
        self.user = UserApi()
        self.authorization = self.user.get_authorization()
        self.course = CourseApi()

        self.now = strftime("%Y%m%d%H%M%S")


    @pytest.fixture(scope="class")
    def get_userIds(self):
        '''方法前置 - 创建kidId'''
        # 创建小孩账户
        couerseList = self.course.listAllWithLevel(self.authorization)["data"]
        yield couerseList

    @pytest.mark.release
    def test_user_videoWhitelist_update_normal(self, get_userIds):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        userIds = get_userIds
        event_res = self.user.update_videoWhitelist(self.authorization, userIds)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_videoWhitelist_update_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        userIds = []
        event_res = self.user.update_videoWhitelist(self.authorization, userIds)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_videoWhitelist_update_wrong(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        userIds = [111, -9999, "~!@#", "", ()]
        event_res = self.user.update_videoWhitelist(self.authorization, userIds)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_bindWechat_normal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        code = "18380143661"
        event_res = self.user.bindWechat(self.authorization, code)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"

    @pytest.mark.release
    def test_user_bindWechat_abnormal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        code = "18380143661"
        event_res = self.user.bindWechat(self.authorization, code)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'WeChat authorization code is invalid'
        assert event_res["data"] == 'WeChat authorization code is invalid'

    @pytest.mark.release
    @pytest.mark.parametrize("code", [123, 123.4, True, "!@#~"], ids=["integer", "float", "boolen", "special characters"])
    def test_user_bindWechat_wrong(self, code):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.bindWechat(self.authorization, code)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'WeChat authorization code is invalid'
        assert event_res["data"] == 'WeChat authorization code is invalid'

    @pytest.mark.release
    def test_user_bindWechat_null(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.bindWechat(self.authorization, '')
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'WeChat authorization code is invalid'

    @pytest.mark.release
    def test_user_bindWechat_withoutCode(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pl = {"pop_item": "code"}
        event_res = self.user.bindWechat(self.authorization, '', **pl)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'WeChat authorization code is invalid'

    @pytest.mark.release
    def test_user_bindWechat_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        code = "18380143661"
        self.user.bindWechat('', code, status_code=401)

    @pytest.mark.release
    def test_user_unbindWechat_abnormal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.unbindWechat(self.authorization)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_unbindWechat_normal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.unbindWechat(self.authorization)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_unbindWechat_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.unbindWechat('', code=403)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_bindApple_normal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        identifyToken = "18380143661"
        event_res = self.user.bindApple(self.authorization, identifyToken)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    @pytest.mark.parametrize("identifyToken", [123, 123.4, True, "!@#~"], ids=["integer", "float", "boolen", "special characters"])
    def test_user_bindApple_wrong(self, identifyToken):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.bindApple(self.authorization, identifyToken=identifyToken)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_bindApple_null(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.bindApple(self.authorization)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_bindApple_withReq(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pl = {
            "pop_item": "identifyToken"
        }
        event_res = self.user.bindApple(self.authorization, **pl)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_bindApple_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        identifyToken = "18380143661"
        event_res = self.user.bindApple('', identifyToken)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_unbindApple_normal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.unbindApple(self.authorization)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.release
    def test_user_unbindApple_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        code = "18380143661"
        event_res = self.user.unbindApple('', code=403)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    def test_noargs_auto_basic(self):
        """AI创建故事书消耗giggles"""
        res = self.api.auto(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'



    def test_user_positive_getAzureconfig_ok(self):
        """获取 Azure 配置-正向用例"""
        res = self.user.getAzureconfig(authorization=self.authorization, **{})
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'


    def test_user_permission_getAzureconfig_no_auth(self):
        """获取 Azure 配置-未登录"""
        res = self.user.getAzureconfig()
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'


    def test_user_permission_getAzureconfig_expired_token(self):
        """获取 Azure 配置-鉴权异常-expired_token"""
        res = self.user.getAzureconfig(authorization='expired_token')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'


    def test_user_permission_getAzureconfig_invalid_token(self):
        """获取 Azure 配置-鉴权异常-invalid_token"""
        res = self.user.getAzureconfig(authorization='invalid_token')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'
