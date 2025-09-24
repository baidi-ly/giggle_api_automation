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
        res = self.donate.createdonateorder(authorization=self.authorization, amount='', donorName='', anonymous=False, currency='', donorType='', donorEmailAddress='', fundSource='', message='', platform='', donateChannel='', networkType='', transactionId='')
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
        res = self.donate.createdonateorder(input_param, amount='', donorName='', anonymous=False, currency='', donorType='', donorEmailAddress='', fundSource='', message='', platform='', donateChannel='', networkType='', transactionId='')
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
    def test_donate_required_createdonateorder_amount(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(amount)"""
        if desc == 'missing':
            pl, amount = {'pop_items': 'amount'}, 0
        else:
            pl, amount = {}, value
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
    def test_donate_format_createdonateorder_amount(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(amount)"""
        res = self.donate.createdonateorder(self.authorization, amount=value)
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
    def test_donate_boundary_createdonateorder_amount(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(amount)"""
        res = self.donate.createdonateorder(self.authorization, amount=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_amount(self):
        """创建捐赠订单-场景异常-无效的amount"""
        test_params = {}
        test_params['amount'] = 'INVALID_VALUE'
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_amount(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(amount)"""
        test_params = {}
        test_params['amount'] = attack_value
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_donorName(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(donorName)"""
        if desc == 'missing':
            pl, donorName = {'pop_items': 'donorName'}, 0
        else:
            pl, donorName = {}, value
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
    def test_donate_format_createdonateorder_donorName(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(donorName)"""
        res = self.donate.createdonateorder(self.authorization, donorName=value)
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
    def test_donate_boundary_createdonateorder_donorName(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(donorName)"""
        res = self.donate.createdonateorder(self.authorization, donorName=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_donorName(self):
        """创建捐赠订单-场景异常-无效的donorName"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = 'INVALID_VALUE'
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_donorName(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(donorName)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = attack_value
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_anonymous(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(anonymous)"""
        if desc == 'missing':
            pl, anonymous = {'pop_items': 'anonymous'}, 0
        else:
            pl, anonymous = {}, value
        res = self.donate.createdonateorder(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('string', '字符串', '"abc"'),
            ('integer', '整数', 123),
            ('float', '浮点数', 12.34),
            ('array', '数组', [1, 2, 3]),
            ('object', '对象', {'key': 'value'}),
            ('special_chars', '特殊字符', '"!@#$%^&*()"'),
            ('emoji', '表情符号', '"😀🎉🚀"'),
            ('long_string', '超长字符串', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_donate_format_createdonateorder_anonymous(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(anonymous)"""
        res = self.donate.createdonateorder(self.authorization, anonymous=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_anonymous(self):
        """创建捐赠订单-场景异常-无效的anonymous"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = 'INVALID_VALUE'
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_currency(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(currency)"""
        if desc == 'missing':
            pl, currency = {'pop_items': 'currency'}, 0
        else:
            pl, currency = {}, value
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
    def test_donate_format_createdonateorder_currency(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(currency)"""
        res = self.donate.createdonateorder(self.authorization, currency=value)
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
    def test_donate_boundary_createdonateorder_currency(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(currency)"""
        res = self.donate.createdonateorder(self.authorization, currency=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_currency(self):
        """创建捐赠订单-场景异常-无效的currency"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = 'INVALID_VALUE'
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_currency(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(currency)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = attack_value
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_donorType(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(donorType)"""
        if desc == 'missing':
            pl, donorType = {'pop_items': 'donorType'}, 0
        else:
            pl, donorType = {}, value
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
    def test_donate_format_createdonateorder_donorType(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(donorType)"""
        res = self.donate.createdonateorder(self.authorization, donorType=value)
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
    def test_donate_boundary_createdonateorder_donorType(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(donorType)"""
        res = self.donate.createdonateorder(self.authorization, donorType=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_donorType(self):
        """创建捐赠订单-场景异常-无效的donorType"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = 'INVALID_VALUE'
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_donorType(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(donorType)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = attack_value
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_donorEmailAddress(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(donorEmailAddress)"""
        if desc == 'missing':
            pl, donorEmailAddress = {'pop_items': 'donorEmailAddress'}, 0
        else:
            pl, donorEmailAddress = {}, value
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
    def test_donate_format_createdonateorder_donorEmailAddress(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(donorEmailAddress)"""
        res = self.donate.createdonateorder(self.authorization, donorEmailAddress=value)
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
    def test_donate_boundary_createdonateorder_donorEmailAddress(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(donorEmailAddress)"""
        res = self.donate.createdonateorder(self.authorization, donorEmailAddress=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_donorEmailAddress(self):
        """创建捐赠订单-场景异常-无效的donorEmailAddress"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = 'INVALID_VALUE'
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_donorEmailAddress(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(donorEmailAddress)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = attack_value
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_fundSource(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(fundSource)"""
        if desc == 'missing':
            pl, fundSource = {'pop_items': 'fundSource'}, 0
        else:
            pl, fundSource = {}, value
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
    def test_donate_format_createdonateorder_fundSource(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(fundSource)"""
        res = self.donate.createdonateorder(self.authorization, fundSource=value)
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
    def test_donate_boundary_createdonateorder_fundSource(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(fundSource)"""
        res = self.donate.createdonateorder(self.authorization, fundSource=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_fundSource(self):
        """创建捐赠订单-场景异常-无效的fundSource"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = 'INVALID_VALUE'
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_fundSource(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(fundSource)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = attack_value
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_message(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(message)"""
        if desc == 'missing':
            pl, message = {'pop_items': 'message'}, 0
        else:
            pl, message = {}, value
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
    def test_donate_format_createdonateorder_message(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(message)"""
        res = self.donate.createdonateorder(self.authorization, message=value)
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
    def test_donate_boundary_createdonateorder_message(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(message)"""
        res = self.donate.createdonateorder(self.authorization, message=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_message(self):
        """创建捐赠订单-场景异常-无效的message"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = 'INVALID_VALUE'
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_message(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(message)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = attack_value
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_platform(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(platform)"""
        if desc == 'missing':
            pl, platform = {'pop_items': 'platform'}, 0
        else:
            pl, platform = {}, value
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
    def test_donate_format_createdonateorder_platform(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(platform)"""
        res = self.donate.createdonateorder(self.authorization, platform=value)
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
    def test_donate_boundary_createdonateorder_platform(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(platform)"""
        res = self.donate.createdonateorder(self.authorization, platform=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_platform(self):
        """创建捐赠订单-场景异常-无效的platform"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = 'INVALID_VALUE'
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_platform(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(platform)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = attack_value
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_donateChannel(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(donateChannel)"""
        if desc == 'missing':
            pl, donateChannel = {'pop_items': 'donateChannel'}, 0
        else:
            pl, donateChannel = {}, value
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
    def test_donate_format_createdonateorder_donateChannel(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(donateChannel)"""
        res = self.donate.createdonateorder(self.authorization, donateChannel=value)
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
    def test_donate_boundary_createdonateorder_donateChannel(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(donateChannel)"""
        res = self.donate.createdonateorder(self.authorization, donateChannel=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_donateChannel(self):
        """创建捐赠订单-场景异常-无效的donateChannel"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = 'INVALID_VALUE'
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_donateChannel(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(donateChannel)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = attack_value
        test_params['networkType'] = ''
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_networkType(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(networkType)"""
        if desc == 'missing':
            pl, networkType = {'pop_items': 'networkType'}, 0
        else:
            pl, networkType = {}, value
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
    def test_donate_format_createdonateorder_networkType(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(networkType)"""
        res = self.donate.createdonateorder(self.authorization, networkType=value)
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
    def test_donate_boundary_createdonateorder_networkType(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(networkType)"""
        res = self.donate.createdonateorder(self.authorization, networkType=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_networkType(self):
        """创建捐赠订单-场景异常-无效的networkType"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = 'INVALID_VALUE'
        test_params['transactionId'] = ''
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
    def test_donate_security_createdonateorder_networkType(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(networkType)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = attack_value
        test_params['transactionId'] = ''
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
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
    def test_donate_required_createdonateorder_transactionId(self, input_param, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(transactionId)"""
        if desc == 'missing':
            pl, transactionId = {'pop_items': 'transactionId'}, 0
        else:
            pl, transactionId = {}, value
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
    def test_donate_format_createdonateorder_transactionId(self, input_param, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(transactionId)"""
        res = self.donate.createdonateorder(self.authorization, transactionId=value)
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
    def test_donate_boundary_createdonateorder_transactionId(self, input_param, desc, value):
        """创建捐赠订单-边界值测试-{desc}(transactionId)"""
        res = self.donate.createdonateorder(self.authorization, transactionId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_scenario_createdonateorder_invalid_transactionId(self):
        """创建捐赠订单-场景异常-无效的transactionId"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = 'INVALID_VALUE'
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
    def test_donate_security_createdonateorder_transactionId(self, test_type, test_desc, attack_value):
        """创建捐赠订单-安全测试-{test_desc}(transactionId)"""
        test_params = {}
        test_params['amount'] = ''
        test_params['donorName'] = ''
        test_params['anonymous'] = False
        test_params['currency'] = ''
        test_params['donorType'] = ''
        test_params['donorEmailAddress'] = ''
        test_params['fundSource'] = ''
        test_params['message'] = ''
        test_params['platform'] = ''
        test_params['donateChannel'] = ''
        test_params['networkType'] = ''
        test_params['transactionId'] = attack_value
        res = self.donate.createdonateorder(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

