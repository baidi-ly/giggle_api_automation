import datetime
import sys
import os
from pandas import DataFrame

from test_case.page_api.donate.donate_api import DonateApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.donate
class TestDonate:

    def setup_class(self):
        self.doante = DonateApi()
        self.authorization = self.game.get_authorization()

    @pytest.mark.release
    def test_donate_positive_createdonateorder_ok(self):
        """创建捐赠订单-正向用例"""
        res = self.donate.createdonateorder(authorization=self.authorization, request='')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('unauthorized', '未登录', 'missing'),
            ('no_auth', '空token', ''),
            ('expired_token', '鉴权异常-expired_token', 'expired_token'),
            ('invalid_token', '鉴权异常-invalid_token', 'invalid_token'),
        ]
    )
    def test_donate_permission_createdonateorder(self, input_param, desc, value):
        """创建捐赠订单-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.donate.createdonateorder(input_param, request='')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('missing', '缺失',  'missing'),
            ('empty', '为空', "''"),
            ('null', 'None', None),
        ]
    )
    def test_donate_required_createdonateorder_request(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(request)"""
        if desc == 'missing':
            pl, request = {'pop_items': 'request'}, 0
        else:
            pl, request = {}, value
        res = self.donate.createdonateorder(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('integer', '整数', 123),
            ('float', '浮点数', 12.34),
            ('boolean', '布尔值', True),
            ('array', '数组', [1, 2, 3]),
            ('object', '对象', {'key': 'value'}),
            ('special_chars', '特殊字符', '"!@#$%^&*()"'),
            ('email_format', '邮箱格式', '"test@example.com"'),
            ('phone_format', '手机号格式', '"13800138000"'),
            ('date_format', '日期格式', '"2023-12-25"'),
            ('emoji', '表情符号', '"😀🎉🚀"'),
            ('long_string', '超长字符串', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
            ('unicode', 'Unicode字符', '"中文测试"'),
            ('sql_injection', 'SQL注入', '"\'; DROP TABLE users; --"'),
            ('xss', 'XSS攻击', '"<script>alert(1)</script>"'),
            ('json_string', 'JSON字符串', '"{\\"key\\": \\"value\\"}"'),
            ('xml_string', 'XML字符串', '"<root><item>test</item></root>"'),
            ('url_string', 'URL字符串', '"https://www.example.com"'),
            ('base64_string', 'Base64字符串', '"SGVsbG8gV29ybGQ="'),
        ]
    )
    def test_donate_format_createdonateorder_request(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(request)"""
        res = self.donate.createdonateorder(self.authorization, request=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('shortest', '最短长度', ""),
            ('longest', '最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_request(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(request)"""
        res = self.donate.createdonateorder(self.authorization, request=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_request(self):
        """创建捐赠订单-场景异常-无效的request"""
        test_params = {}
        test_params['request'] = 'INVALID_VALUE'
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
            ('sql_injection', 'SQL注入', "' OR 1=1 --"),
            ('xss_attack', 'XSS攻击', "<script>alert('xss')</script>"),
        ]
    )
    def test_donate_security_createdonateorder_request(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(request)"""
        test_params = {}
        test_params['request'] = attack_value
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

