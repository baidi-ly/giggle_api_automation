import datetime
import json
import sys
import os
from time import strftime

from pandas import DataFrame

from test_case.page_api.activity.activity_api import ActivityApi
from test_case.page_api.admin.admin_activity_api import AdminActivityApi
from test_case.page_api.admin.admin_banner_api import AdminBannerApi
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.user.user_api import UserApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.activity
class TestActivity:

    def setup_class(self):
        self.activity = ActivityApi()
        self.admin_banner = AdminBannerApi()
        self.authorization, self.userId = self.activity.get_authorization()
        self.kid = KidApi()
        self.user = UserApi()
        self.course = CourseApi()
        self.adminActivity = AdminActivityApi()
        self.admin_auth, self.user_adminId = self.adminActivity.get_admin_authorization()
        self.now = strftime("%Y%m%d%H%M%S")

        try:
            kids_res = self.kid.getKids(self.authorization)
            self.kid_name = 'New Kid'
            for kid in kids_res['data']:
                if kid['name'] == self.kid_name:
                    self.kid_id = kid['id']
                    break
        except Exception as e:
            print(f'获取孩子失败，原因是：{e}')

    @pytest.fixture(scope="class")
    def getkidId(self):
        '''类前置 - 获取kidId'''
        kidId = self.kid.getKids(self.authorization)
        yield kidId

    @pytest.fixture(scope="class")
    def getUserKids(self):
        '''类前置 - 获取kidId'''
        kidId = self.user.getUserKids(self.authorization)
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
        res = self.activity.userGachaInfo(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']

    @pytest.mark.smoke
    def test_activity_positive_activity_gacha_ok(self, getUserKids):
        """获取用户抽奖信息-正向用例"""
        kidId = getUserKids['data'][1]['id']
        activity_res = self.activity.getInfo(authorization=self.authorization)['data']
        activityId = activity_res['activityId']
        res = self.activity.userGachaInfo(self.authorization, activityId, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['drawCount'] == 1, "日常抽奖次数不为1！"

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
        res = self.activity.userGachaInfo(value, activityId=1, kidId=kidId, code=401)

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
        res = self.activity.userGachaInfo(self.authorization, kidId=kidId, activityId=activityId, code=code, **pl)
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
        res = self.activity.userGachaInfo(self.authorization, kidId=kidId, activityId=value, code=code)
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
        res = self.activity.userGachaInfo(self.authorization, kidId=kidId, activityId=value)
        assert res['code'] == 100114
        assert res['message'] == 'Activity not found'
        assert res['data'] == 'Activity not found'

    def test_activity_scenario_getInfo1_invalid_activityId(self, getkidId):
        """获取用户抽奖信息-场景异常-无效的activityId"""
        kidId = getkidId[0]["id"]
        res = self.activity.userGachaInfo(self.authorization, kidId=kidId, activityId=99999)
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
        res = self.activity.userGachaInfo(self.authorization, kidId=kidId, code=code, **pl)
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
        res = self.activity.userGachaInfo(self.authorization, kidId=value, code=400)
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
        res = self.activity.userGachaInfo(self.authorization, kidId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100105
        assert res['message'] == 'Kid id not exist'
        assert res['data'] == 'Kid id not exist'

    def test_activity_scenario_getInfo1_invalid_kidId(self):
        """获取用户抽奖信息-场景异常-无效的kidId"""
        res = self.activity.userGachaInfo(authorization=self.authorization, kidId=99999999)
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

    @pytest.mark.smoke
    def test_activity_positive_getList_ok(self):
        """获取当前正在进行的扭蛋活动-正向用例"""
        res = self.activity.getList(self.authorization)
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
    def test_activity_permission_getList(self, desc, value):
        """获取当前正在进行的扭蛋活动-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.getList(value)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

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

    def test_activity_scenario_getList_invalid_language(self):
        """获取当前正在进行的扭蛋活动-场景异常-无效的language"""
        language = 'INVALID_VALUE'
        res = self.activity.getList(self.authorization, language=language)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
        assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
        assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

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

    @pytest.mark.smoke
    def test_activity_positive_getCoursecompleteactivityid_ok(self):
        """获取完课活动ID-正向用例"""
        res = self.activity.getCoursecompleteactivityid(self.authorization)
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
    def test_activity_permission_getCoursecompleteactivityid(self, desc, value):
        """获取完课活动ID-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.getCoursecompleteactivityid(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
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

    def test_activity_scenario_coursecompleteactivityid_invalid_activityId(self):
        """配置完课活动ID-场景异常-无效的activityId"""
        activityId = 999999999
        res = self.activity.coursecompleteactivityid(self.authorization, activityId=activityId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100114, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'Activity not found', f"接口返回message信息异常: 预期【Activity not found】，实际【{res['message']}】"
        assert res['data'] == 'Activity not found', f"接口返回data数据异常：{res['data']}"

    @pytest.fixture(scope="class")
    def create_task(self, create_activity):
        '''创建完课扭蛋活动'''
        # 创建活动
        activity_name = "Daily Course Complete Gacha" + self.now
        startTime = (datetime.date.today() + datetime.timedelta(days=-1)).strftime("%Y-%m-%d %H:%M:%S")  # 昨天
        endTime = (datetime.date.today() + datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")  # 明天
        pl = {
            "name": activity_name,
            "activityCode": "GACHA",
            "startTime": startTime,
            "endTime": endTime,
            "status": "ACTIVE",
            "tags": ["COURSE_COMPLETE"]
        }
        activity_id = self.adminActivity.activity_create(self.admin_auth, **pl)['data']['id']
        # 创建活动任务定义
        task_name = "每日完课增加抽奖次数" + self.now
        pl1 = {
            "activityId": activity_id,         # 你刚创建的活动ID
            "actionCode": "COURSE_COMPLETE",   # 必须精准写这个
            "name": task_name,
            "general": False,
            "rewardType": "DRAWS",             # 或者 "POINTS"，看你想给什么奖励
            "rewardValue": 1,                  # 比如 +1 次抽奖
            "maxTimes": 1,
            "config": None
        }
        activity_task_id = self.adminActivity.create_activity_task(self.admin_auth, **pl1)['data']['id']
        yield
        # 删除活动任务定义
        self.adminActivity.delete_activity_task(self.admin_auth, activity_task_id)
        # 更新活动状态为无效
        self.adminActivity.updateActivityStatus(self.admin_auth, activity_id, status='INACTIVE')

    @pytest.mark.smoke
    def test_activity_positive_dailyLessonComplete_ok(self, create_task):
        """根据每日学习计划课程完成增加抽奖次数-正向用例"""
        # 根据每日学习计划课程完成增加抽奖次数前，确认今天没有通过每日课程完成增加过抽奖次数
        check_before = self.activity.dailyLessonCompleteCheck(self.authorization, self.kid_id)
        assert check_before['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{check_before['code']}】"
        assert check_before['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{check_before['message']}】"
        assert check_before['data']['granted'] == False, f"接口返回data数据异常：{check_before['data']}"
        # 通过查询晋级资格获取学生level
        learningLevel = self.course.promotion_check(self.authorization, self.kid_id)['data']['currentLevel']
        # 根据level获取课程推荐列表
        recommends_res = self.course.course_recommends(self.authorization, self.kid_id, learningLevel)['data'][:2]
        courseIds = ','.join(DataFrame(recommends_res)['id'].tolist())
        # 根据每日学习计划课程完成增加抽奖次数
        res = self.activity.dailyLessonComplete(self.authorization, courseIds, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        # 根据每日学习计划课程完成增加抽奖次数后，确认今天已经通过每日课程完成增加过抽奖次数
        check_after = self.activity.dailyLessonCompleteCheck(self.authorization, self.kid_id)
        assert check_after['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert check_after['message'] == 'success', f"接口返回message信息异常: 预期【Activity not found】，实际【{res['message']}】"
        assert check_after['data'], f"接口返回data数据异常：{res['data']}"


    @pytest.mark.smoke
    def test_activity_positive_getCheckByCourses_ok(self, get_course_ids_session, kid_data_session):
        """根据课程id列表,查询是否已经通过每日课程完成增加过抽奖次数"""
        # 获取课程详情包括版本信息
        courseIds = get_course_ids_session[:2]
        # 创建测试学生
        kid_id, kid_name = kid_data_session
        # 据课程id列表, 查询是否已经通过每日课程完成增加过抽奖次数
        res1 = self.activity.getCheckByCourses(self.authorization, courseIds, kid_id)
        for courseId in courseIds:
            assert not res1['data'][courseId]
        # 根据每日学习计划课程完成增加抽奖次数
        lessonComplete_res = self.activity.dailyLessonComplete(self.authorization, courseIds, kid_id)
        assert lessonComplete_res['message'] == 'success'
        # 据课程id列表, 查询是否已经通过每日课程完成增加过抽奖次数
        res2 = self.activity.getCheckByCourses(self.authorization, courseIds, kid_id)
        for courseId in courseIds:
            assert res2['data'][courseId]
