import datetime
import json
import sys
import os
from time import strftime

from test_case.page_api.activity.activity_api import ActivityApi
from test_case.page_api.admin.admin_activity_api import AdminActivityApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.activity
class TestActivity:

    def setup_class(self):
        self.activity = ActivityApi()
        self.authorization = self.activity.get_authorization()
        self.kid = KidApi()
        self.adminActivity = AdminActivityApi()
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.fixture(scope="class")
    def getkidId(self):
        '''类前置 - 获取kidId'''
        kidId = self.kid.getKids(self.authorization)
        yield kidId

    @pytest.fixture(scope="class")
    def create_activity(self):
        res = self.adminActivity.getList(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_activity_positive_getInfo_ok(self):
        """获取扭蛋当前活动信息-正向用例"""
        res = self.activity.getInfo(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['activityId'] == 720712510713925
        assert res['data']['activityName'] == '扭蛋活动-国庆'
        assert res['data']['activityStatus'] == 'ACTIVE'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_activity_permission_getInfo(self, desc, value):
        """获取扭蛋当前活动信息-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.getInfo(value, code=401)

    @pytest.mark.release
    def test_activity_positive_getInfo1_ok(self, getkidId):
        """获取用户抽奖信息-正向用例"""
        kidId = getkidId[0]["id"]
        res = self.activity.getInfo1(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_activity_permission_getInfo1(self, desc, value, getkidId):
        """获取用户抽奖信息-{desc}"""
        kidId = getkidId[0]["id"]
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.getInfo1(value, activityId=1, kidId=kidId, code=401)

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "''", 400),
            ('null', None, 500),
        ]
    )
    def test_activity_required_getInfo1_activityId(self, desc, value, code, getkidId):
        """获取用户抽奖信息-必填字段测试-{desc}(activityId)"""
        kidId = getkidId[0]["id"]
        if desc == 'missing':
            pl, activityId = {'pop_items': 'activityId'}, 1
        else:
            pl, activityId, kidId = {}, value, kidId
        res = self.activity.getInfo1(self.authorization, kidId=kidId, activityId=activityId, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == code
            assert res['message'] == 'internal server error'
            assert res['data']['message'] == "Required request parameter 'activityId' for method parameter type long is not present"
        else:
            assert res['code'] == 100006
            assert res['message'] == 'invalid parameter'
            assert res['data'] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: "''"'''


    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', '"abc"'),
            ('float', 12.34),
            ('boolean', True),
            ('array', [1, 2, 3]),   #   TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_activity_format_getInfo1_activityId(self, desc, value, getkidId):
        """获取用户抽奖信息-数据格式测试-{desc}(activityId)"""
        kidId = getkidId[0]["id"]
        code = 400 if desc not in ['special_chars', 'emoji'] else 403
        res = self.activity.getInfo1(self.authorization, kidId=kidId, activityId=value, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if desc not in ['special_chars', 'emoji']:
            assert res['code'] == 100006
            assert res['message'] == 'invalid parameter'
            assert '''Failed to convert value of type 'java.lang.String' to required type 'long'; ''' in res['data']
        else:
            assert res['code'] == 100114
            assert res['message'] == 'Activity not found'
            assert res['data'] == 'Activity not found'


    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),   # TODO
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_activity_boundary_getInfo1_activityId(self, desc, value, getkidId):
        """获取用户抽奖信息-边界值测试-{desc}(activityId)"""
        kidId = getkidId[0]["id"]
        res = self.activity.getInfo1(self.authorization, kidId=kidId, activityId=value)
        assert res['code'] == 100114
        assert res['message'] == 'Activity not found'
        assert res['data'] == 'Activity not found'

    @pytest.mark.release
    def test_activity_scenario_getInfo1_invalid_activityId(self, getkidId):
        """获取用户抽奖信息-场景异常-无效的activityId"""
        kidId = getkidId[0]["id"]
        res = self.activity.getInfo1(self.authorization, kidId=kidId, activityId=99999)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100114
        assert res['message'] == 'Activity not found'
        assert res['data'] == 'Activity not found'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "''", 400),
            ('null', None, 500),
        ]
    )
    def test_activity_required_getInfo1_kidId(self, desc, value, code, create_activity):
        """获取用户抽奖信息-必填字段测试-{desc}(kidId)"""
        if desc == 'missing':
            pl, kidId = {'pop_items': 'kidId'}, 0
        else:
            pl, kidId = {}, value
        res = self.activity.getInfo1(self.authorization, kidId=kidId, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == code
            assert res['message'] == 'internal server error'
            assert res['data']['message'] == "Required request parameter 'kidId' for method parameter type long is not present"
        else:
            assert res['code'] == 100006
            assert res['message'] == 'invalid parameter'
            assert res['data'] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: "''"'''

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),
            ('boolean',  True),
            ('array', [1, 2, 3]),  # TODO
            ('object',  {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),  # TODO
            ('emoji', '😀🎉🚀'),   # TODO
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
        ]
    )
    def test_activity_format_getInfo1_kidId(self, desc, value):
        """获取用户抽奖信息-数据格式测试-{desc}(kidId)"""
        res = self.activity.getInfo1(self.authorization, kidId=value, code=400)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100006
        assert res['message'] == 'invalid parameter'
        assert '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: ''' in res['data']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),   # TODO
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_activity_boundary_getInfo1_kidId(self, desc, value):
        """获取用户抽奖信息-边界值测试-{desc}(kidId)"""
        res = self.activity.getInfo1(self.authorization, kidId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100105
        assert res['message'] == 'Kid id not exist'
        assert res['data'] == 'Kid id not exist'

    @pytest.mark.release
    def test_activity_scenario_getInfo1_invalid_kidId(self):
        """获取用户抽奖信息-场景异常-无效的kidId"""
        res = self.activity.getInfo1(authorization=self.authorization, kidId=99999999)
        assert res['code'] == 100105
        assert res['message'] == 'Kid id not exist'
        assert res['data'] == 'Kid id not exist'

