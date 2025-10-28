import datetime
import json
import sys
import os
from time import strftime

from pandas import DataFrame

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
        self.authorization = self.activity.get_authorization()[0]
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

    def test_activity_positive_getInfo_ok(self):
        """获取扭蛋当前活动信息-正向用例"""
        res = self.activity.getInfo(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['activityId'] == 720712510713925
        assert res['data']['activityName'] == '扭蛋活动-国庆'
        assert res['data']['activityStatus'] == 'ACTIVE'

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

    def test_activity_positive_getInfo1_ok(self, getkidId):
        """获取用户抽奖信息-正向用例"""
        kidId = getkidId[0]["id"]
        res = self.activity.getInfo1(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']

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

    def test_activity_scenario_getInfo1_invalid_activityId(self, getkidId):
        """获取用户抽奖信息-场景异常-无效的activityId"""
        kidId = getkidId[0]["id"]
        res = self.activity.getInfo1(self.authorization, kidId=kidId, activityId=99999)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100114
        assert res['message'] == 'Activity not found'
        assert res['data'] == 'Activity not found'

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

    def test_activity_scenario_getInfo1_invalid_kidId(self):
        """获取用户抽奖信息-场景异常-无效的kidId"""
        res = self.activity.getInfo1(authorization=self.authorization, kidId=99999999)
        assert res['code'] == 100105
        assert res['message'] == 'Kid id not exist'
        assert res['data'] == 'Kid id not exist'

    def test_activity_positive_share_ok(self, getkidId):
        """分享成功，增加抽奖次数-正向用例"""
        kidId = getkidId[0]["id"]
        res = self.activity.share(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']

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
        """分享成功，增加抽奖次数-{desc}"""
        kidId = getkidId[0]["id"]
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.share(value, kidId=kidId, code=401)

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing', 'missing', 500),
            ('empty', "''", 400),
            ('null', None, 500),
        ]
    )
    def test_activity_required_share_activityId(self, desc, value, code, getkidId):
        """分享成功，增加抽奖次数-必填字段测试-{desc}(activityId)"""
        kidId = getkidId[0]["id"]
        if desc == 'missing':
            pl, activityId = {'pop_items': 'activityId'}, 1
        else:
            pl, activityId, kidId = {}, value, kidId
        res = self.activity.share(self.authorization, kidId=kidId, activityId=activityId, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == code
            assert res['message'] == 'internal server error'
            assert res['data'][
                       'message'] == "Required request parameter 'activityId' for method parameter type long is not present"
        else:
            assert res['code'] == 100006
            assert res['message'] == 'invalid parameter'
            assert res[
                       'data'] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: "''"'''

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', '"abc"'),
            ('float', 12.34),
            ('boolean', True),
            ('array', [1, 2, 3]),  # TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '���'),
            ('long_string',
             '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_activity_format_share_activityId(self, desc, value, getkidId):
        """分享成功，增加抽奖次数-数据格式测试-{desc}(activityId)"""
        kidId = getkidId[0]["id"]
        code = 400 if desc not in ['special_chars', 'emoji'] else 403
        res = self.activity.share(self.authorization, kidId=kidId, activityId=value, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if desc not in ['special_chars', 'emoji']:
            assert res['code'] == 100006
            assert res['message'] == 'invalid parameter'
            assert '''Failed to convert value of type 'java.lang.String' to required type 'long'; ''' in res['data']
        else:
            assert res['code'] == 100114
            assert res['message'] == 'Activity not found'
            assert res['data'] == 'Activity not found'

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),  # TODO
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_activity_boundary_share_activityId(self, desc, value, getkidId):
        """分享成功，增加抽奖次数-边界值测试-{desc}(activityId)"""
        kidId = getkidId[0]["id"]
        res = self.activity.share(self.authorization, kidId=kidId, activityId=value)
        assert res['code'] == 100114
        assert res['message'] == 'Activity not found'
        assert res['data'] == 'Activity not found'

    def test_activity_scenario_share_invalid_activityId(self, getkidId):
        """分享成功，增加抽奖次数-场景异常-无效的activityId"""
        kidId = getkidId[0]["id"]
        res = self.activity.share(self.authorization, kidId=kidId, activityId=99999)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100114
        assert res['message'] == 'Activity not found'
        assert res['data'] == 'Activity not found'

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing', 'missing', 500),
            ('empty', "''", 400),
            ('null', None, 500),
        ]
    )
    def test_activity_required_share_kidId(self, desc, value, code, create_activity):
        """分享成功，增加抽奖次数-必填字段测试-{desc}(kidId)"""
        if desc == 'missing':
            pl, kidId = {'pop_items': 'kidId'}, 0
        else:
            pl, kidId = {}, value
        res = self.activity.share(self.authorization, kidId=kidId, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == code
            assert res['message'] == 'internal server error'
            assert res['data'][
                       'message'] == "Required request parameter 'kidId' for method parameter type long is not present"
        else:
            assert res['code'] == 100006
            assert res['message'] == 'invalid parameter'
            assert res[
                       'data'] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: "''"'''

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),
            ('boolean', True),
            ('array', [1, 2, 3]),  # TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),  # TODO
            ('emoji', '���'),  # TODO
            ('long_string',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
        ]
    )
    def test_activity_format_share_kidId(self, desc, value):
        """分享成功，增加抽奖次数-数据格式测试-{desc}(kidId)"""
        res = self.activity.share(self.authorization, kidId=value, code=400)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100006
        assert res['message'] == 'invalid parameter'
        assert '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: ''' in \
               res['data']

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),  # TODO
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_activity_boundary_share_kidId(self, desc, value):
        """分享成功，增加抽奖次数-边界值测试-{desc}(kidId)"""
        res = self.activity.share(self.authorization, kidId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100105
        assert res['message'] == 'Kid id not exist'
        assert res['data'] == 'Kid id not exist'

    def test_activity_scenario_share_invalid_kidId(self):
        """分享成功，增加抽奖次数-场景异常-无效的kidId"""
        res = self.activity.share(authorization=self.authorization, kidId=99999999)
        assert res['code'] == 100105
        assert res['message'] == 'Kid id not exist'
        assert res['data'] == 'Kid id not exist'

    def test_activity_positive_draw_ok(self, getkidId):
        """抽奖-正向用例"""
        kidId = getkidId[0]["id"]
        res = self.activity.draw(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_activity_permission_draw(self, desc, value, getkidId):
        """抽奖-{desc}"""
        kidId = getkidId[0]["id"]
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.draw(value, kidId=kidId, code=401)

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing', 'missing', 500),
            ('empty', "''", 400),
            ('null', None, 500),
        ]
    )
    def test_activity_required_draw_activityId(self, desc, value, code, getkidId):
        """抽奖-必填字段测试-{desc}(activityId)"""
        kidId = getkidId[0]["id"]
        if desc == 'missing':
            pl, activityId = {'pop_items': 'activityId'}, 1
        else:
            pl, activityId, kidId = {}, value, kidId
        res = self.activity.draw(self.authorization, kidId=kidId, activityId=activityId, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == code
            assert res['message'] == 'internal server error'
            assert res['data'][
                       'message'] == "Required request parameter 'activityId' for method parameter type long is not present"
        else:
            assert res['code'] == 100006
            assert res['message'] == 'invalid parameter'
            assert res[
                       'data'] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: "''"'''

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', '"abc"'),
            ('float', 12.34),
            ('boolean', True),
            ('array', [1, 2, 3]),  # TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '���'),
            ('long_string',
             '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_activity_format_draw_activityId(self, desc, value, getkidId):
        """抽奖-数据格式测试-{desc}(activityId)"""
        kidId = getkidId[0]["id"]
        code = 400 if desc not in ['special_chars', 'emoji'] else 403
        res = self.activity.draw(self.authorization, kidId=kidId, activityId=value, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if desc not in ['special_chars', 'emoji']:
            assert res['code'] == 100006
            assert res['message'] == 'invalid parameter'
            assert '''Failed to convert value of type 'java.lang.String' to required type 'long'; ''' in res['data']
        else:
            assert res['code'] == 100114
            assert res['message'] == 'Activity not found'
            assert res['data'] == 'Activity not found'

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),  # TODO
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_activity_boundary_draw_activityId(self, desc, value, getkidId):
        """抽奖-边界值测试-{desc}(activityId)"""
        kidId = getkidId[0]["id"]
        res = self.activity.draw(self.authorization, kidId=kidId, activityId=value)
        assert res['code'] == 100114
        assert res['message'] == 'Activity not found'
        assert res['data'] == 'Activity not found'

    def test_activity_scenario_draw_invalid_activityId(self, getkidId):
        """抽奖-场景异常-无效的activityId"""
        kidId = getkidId[0]["id"]
        res = self.activity.draw(self.authorization, kidId=kidId, activityId=99999)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100114
        assert res['message'] == 'Activity not found'
        assert res['data'] == 'Activity not found'

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing', 'missing', 500),
            ('empty', "''", 400),
            ('null', None, 500),
        ]
    )
    def test_activity_required_draw_kidId(self, desc, value, code, create_activity):
        """抽奖-必填字段测试-{desc}(kidId)"""
        if desc == 'missing':
            pl, kidId = {'pop_items': 'kidId'}, 0
        else:
            pl, kidId = {}, value
        res = self.activity.draw(self.authorization, kidId=kidId, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == code
            assert res['message'] == 'internal server error'
            assert res['data'][
                       'message'] == "Required request parameter 'kidId' for method parameter type long is not present"
        else:
            assert res['code'] == 100006
            assert res['message'] == 'invalid parameter'
            assert res[
                       'data'] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: "''"'''

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),
            ('boolean', True),
            ('array', [1, 2, 3]),  # TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),  # TODO
            ('emoji', '���'),  # TODO
            ('long_string',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
        ]
    )
    def test_activity_format_draw_kidId(self, desc, value):
        """抽奖-数据格式测试-{desc}(kidId)"""
        res = self.activity.draw(self.authorization, kidId=value, code=400)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100006
        assert res['message'] == 'invalid parameter'
        assert '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: ''' in \
               res['data']

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),  # TODO
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_activity_boundary_draw_kidId(self, desc, value):
        """抽奖-边界值测试-{desc}(kidId)"""
        res = self.activity.draw(self.authorization, kidId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100105
        assert res['message'] == 'Kid id not exist'
        assert res['data'] == 'Kid id not exist'

    def test_activity_scenario_draw_invalid_kidId(self):
        """抽奖-场景异常-无效的kidId"""
        res = self.activity.draw(authorization=self.authorization, kidId=99999999)
        assert res['code'] == 100105
        assert res['message'] == 'Kid id not exist'
        assert res['data'] == 'Kid id not exist'


    def test_activity_positive_getRewardcenter_ok(self):
        """扭蛋奖励中心-正向用例"""
        res = self.activity.getRewardcenter(self.authorization)
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
    def test_activity_permission_getRewardcenter(self, desc, value):
        """扭蛋奖励中心-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.getRewardcenter(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_activity_required_getRewardcenter_activityId(self, desc, value):
        """扭蛋奖励中心-必填字段测试(activityId)"""
        if desc == 'missing':
            pl = {'pop_items': 'activityId'}
        else:
            pl = {'activityId': value}
        res = self.activity.getRewardcenter(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),
            ('boolean', True),
            ('negative', -123),
            ('array', [1, 2, 3]),
            ('object', {'key': 'value'}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
        ]
    )
    def test_activity_format_getRewardcenter_activityId(self, desc, value):
        """扭蛋奖励中心-数据格式测试(activityId)"""
        res = self.activity.getRewardcenter(self.authorization, activityId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_activity_boundary_getRewardcenter_activityId(self, desc, value):
        """扭蛋奖励中心-边界值测试(activityId)"""
        res = self.activity.getRewardcenter(self.authorization, activityId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_activity_scenario_getRewardcenter_invalid_activityId(self):
        """扭蛋奖励中心-场景异常-无效的activityId"""
        activityId = 999999999
        res = self.activity.getRewardcenter(self.authorization, activityId=activityId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_activity_required_getRewardcenter_kidId(self, desc, value):
        """扭蛋奖励中心-必填字段测试(kidId)"""
        if desc == 'missing':
            pl = {'pop_items': 'kidId'}
        else:
            pl = {'kidId': value}
        res = self.activity.getRewardcenter(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),
            ('boolean', True),
            ('negative', -123),
            ('array', [1, 2, 3]),
            ('object', {'key': 'value'}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
        ]
    )
    def test_activity_format_getRewardcenter_kidId(self, desc, value):
        """扭蛋奖励中心-数据格式测试(kidId)"""
        res = self.activity.getRewardcenter(self.authorization, kidId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_activity_boundary_getRewardcenter_kidId(self, desc, value):
        """扭蛋奖励中心-边界值测试(kidId)"""
        res = self.activity.getRewardcenter(self.authorization, kidId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_activity_scenario_getRewardcenter_invalid_kidId(self):
        """扭蛋奖励中心-场景异常-无效的kidId"""
        kidId = 999999999
        res = self.activity.getRewardcenter(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_activity_positive_getList_ok(self):
        """获取当前正在进行的扭蛋活动-正向用例"""
        res = self.activity.getList(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

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
    def test_activity_permission_getList(self, desc, value):
        """获取当前正在进行的扭蛋活动-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.getList(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 404),
            ('float', 12.3, 200, 404),
            ('boolean', True, 200, 404),
            ('array', [1, 2, 3], 200, 404),
            ('object', {'key': 'value'}, 200, 404),
            ('special_chars', '!@#$%^&*()', 403, ''),
            ('email_format', 'test@example.com', 403, ''),
            ('phone_format', '13800138000', 200, 404),
            ('date_format', '2023-12-25', 200, 404),
            ('emoji', '😀🎉🚀', '', ''),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 404),
            ('unicode', '中文测试', '', ''),
            ('json_string', '{"key": "value"}', 200, 404),
            ('xml_string', '<root><item>test</item></root>', 200, 404),
            ('url_string', 'https://www.example.com', 403, ''),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 404),
        ]
    )
    def test_activity_format_getList_language(self, desc, value, code, code_res):
        """获取当前正在进行的扭蛋活动-数据格式测试(language)"""
        try:
            res = self.activity.getList(self.authorization, language=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('shortest_length', "", 500),
            ('longest_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 500),
        ]
    )
    def test_activity_boundary_getList_language(self, desc, value, code):
        """获取当前正在进行的扭蛋活动-边界值测试(language)"""
        res = self.activity.getList(self.authorization, language=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
        assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
        assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    def test_activity_scenario_getList_invalid_language(self):
        """获取当前正在进行的扭蛋活动-场景异常-无效的language"""
        language = 'INVALID_VALUE'
        res = self.activity.getList(self.authorization, language=language)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
        assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
        assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('sql_injection', "' OR '1'='1", 403, ''),
            ('xss_script', "<script>alert('XSS')</script>", 403, ''),
            ('xss_img', "<img src=x onerror=alert('XSS')>", 403, ''),
            ('xss_iframe', "<iframe src=javascript:alert('XSS')></iframe>", 403, ''),
            ('xml_injection', "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", 403, ''),
            ('unicode_attack', '\\x00\\x01\\x02', 200, 404),
            ('crlf_injection', 'test%0d%0aSet-Cookie: admin=true', 200, 404),
            ('code_injection', "eval('alert(1)')", 403, ''),
            ('regex_dos', '((a+)+)+$', 403, ''),
        ]
    )
    def test_activity_security_getList_language(self, desc, value, code, code_res):
        """获取当前正在进行的扭蛋活动-安全测试(language)"""
        res = self.activity.getList(self.authorization, language=value, code=code)
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"


    @pytest.mark.release
    def test_activity_positive_getCoursecompleteactivityid_ok(self):
        """获取完课活动ID-正向用例"""
        res = self.activity.getCoursecompleteactivityid(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

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
    def test_activity_permission_getCoursecompleteactivityid(self, desc, value):
        """获取完课活动ID-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.getCoursecompleteactivityid(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"


    @pytest.mark.release
    def test_activity_positive_coursecompleteactivityid_ok(self):
        """配置完课活动ID-正向用例"""
        gacha_res = self.activity.getList(self.authorization)
        activityIds = DataFrame(gacha_res['data'])['activityId'].tolist()
        for activityId in activityIds:
            res = self.activity.coursecompleteactivityid(self.authorization, activityId)
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

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
    def test_activity_permission_coursecompleteactivityid(self, desc, value):
        """配置完课活动ID-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.coursecompleteactivityid(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 400),
            ('null', None, 500),
        ]
    )
    def test_activity_required_coursecompleteactivityid_activityId(self, desc, value, code):
        """配置完课活动ID-必填字段测试(activityId)"""
        if desc == 'missing':
            pl = {'pop_items': 'activityId'}
        else:
            pl = {'activityId': value}
        res = self.activity.coursecompleteactivityid(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常，实际【{res['data']}】"
        else:
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【100006】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常，实际【{res['data']}】"

    @pytest.mark.release
    def test_activity_scenario_coursecompleteactivityid_invalid_activityId(self):
        """配置完课活动ID-场景异常-无效的activityId"""
        activityId = 999999999
        res = self.activity.coursecompleteactivityid(self.authorization, activityId=activityId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100114, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'Activity not found', f"接口返回message信息异常: 预期【Activity not found】，实际【{res['message']}】"
        assert res['data'] == 'Activity not found', f"接口返回data数据异常：{res['data']}"

