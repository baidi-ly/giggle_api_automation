import pytest
import time

from test_case.page_api.donate.donate_api import DonateApi
from config import RunConfig

base_url = RunConfig.baseurl

class TestDonateApi:
    """
    donate 接口测试用例
    """

    def setup_class(self):
        self.donate = DonateApi()
        self.authorization = self.donate.get_authorization()


    @pytest.mark.release
    def test_donate_positive_createdonateorder_ok(self):
        """创建捐赠订单-正向用例"""
        res = self.donate.createdonateorder(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('未登录', 'missing'),
            ('空token', ''),
            ('鉴权异常-expired_token', 'expired_token'),
            ('鉴权异常-invalid_token', 'invalid_token'),
        ]
    )
    def test_donate_permission_createdonateorder(self, desc, value):
        """创建捐赠订单-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.donate.createdonateorder(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_amount(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(amount)"""
        if desc == 'missing':
            pl, amount = {'pop_items': 'amount'}, 0
        else:
            pl, amount = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_donorName(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(donorName)"""
        if desc == 'missing':
            pl, donorName = {'pop_items': 'donorName'}, 0
        else:
            pl, donorName = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_anonymous(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(anonymous)"""
        if desc == 'missing':
            pl, anonymous = {'pop_items': 'anonymous'}, 0
        else:
            pl, anonymous = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_currency(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(currency)"""
        if desc == 'missing':
            pl, currency = {'pop_items': 'currency'}, 0
        else:
            pl, currency = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('整数', 123),
            ('浮点数', 12.3),
            ('布尔值', True),
            ('数组', [1, 2, 3]),
            ('对象', {'key': 'value'}),
            ('特殊字符', '!@#$%^&*()'),
            ('邮箱格式', 'test@example.com'),
            ('手机号格式', '13800138000'),
            ('日期格式', '2023-12-25'),
            ('表情符号', '😀🎉🚀'),
            ('超长字符串', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode字符', '中文测试'),
            ('JSON字符串', '{"key": "value"}'),
            ('XML字符串', '<root><item>test</item></root>'),
            ('URL字符串', 'https://www.example.com'),
            ('Base64字符串', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_createdonateorder_currency(self, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(currency)"""
        res = self.donate.createdonateorder(self.authorization, currency=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('最短长度', ""),
            ('最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_currency(self, desc, value):
        """创建捐赠订单-边界值测试-{desc}(currency)"""
        res = self.donate.createdonateorder(self.authorization, currency=value)
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_donorType(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(donorType)"""
        if desc == 'missing':
            pl, donorType = {'pop_items': 'donorType'}, 0
        else:
            pl, donorType = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('整数', 123),
            ('浮点数', 12.3),
            ('布尔值', True),
            ('数组', [1, 2, 3]),
            ('对象', {'key': 'value'}),
            ('特殊字符', '!@#$%^&*()'),
            ('邮箱格式', 'test@example.com'),
            ('手机号格式', '13800138000'),
            ('日期格式', '2023-12-25'),
            ('表情符号', '😀🎉🚀'),
            ('超长字符串', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode字符', '中文测试'),
            ('JSON字符串', '{"key": "value"}'),
            ('XML字符串', '<root><item>test</item></root>'),
            ('URL字符串', 'https://www.example.com'),
            ('Base64字符串', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_createdonateorder_donorType(self, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(donorType)"""
        res = self.donate.createdonateorder(self.authorization, donorType=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('最短长度', ""),
            ('最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_donorType(self, desc, value):
        """创建捐赠订单-边界值测试-{desc}(donorType)"""
        res = self.donate.createdonateorder(self.authorization, donorType=value)
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_donorEmailAddress(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(donorEmailAddress)"""
        if desc == 'missing':
            pl, donorEmailAddress = {'pop_items': 'donorEmailAddress'}, 0
        else:
            pl, donorEmailAddress = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('整数', 123),
            ('浮点数', 12.3),
            ('布尔值', True),
            ('数组', [1, 2, 3]),
            ('对象', {'key': 'value'}),
            ('特殊字符', '!@#$%^&*()'),
            ('邮箱格式', 'test@example.com'),
            ('手机号格式', '13800138000'),
            ('日期格式', '2023-12-25'),
            ('表情符号', '😀🎉🚀'),
            ('超长字符串', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode字符', '中文测试'),
            ('JSON字符串', '{"key": "value"}'),
            ('XML字符串', '<root><item>test</item></root>'),
            ('URL字符串', 'https://www.example.com'),
            ('Base64字符串', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_createdonateorder_donorEmailAddress(self, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(donorEmailAddress)"""
        res = self.donate.createdonateorder(self.authorization, donorEmailAddress=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('最短长度', ""),
            ('最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_donorEmailAddress(self, desc, value):
        """创建捐赠订单-边界值测试-{desc}(donorEmailAddress)"""
        res = self.donate.createdonateorder(self.authorization, donorEmailAddress=value)
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_fundSource(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(fundSource)"""
        if desc == 'missing':
            pl, fundSource = {'pop_items': 'fundSource'}, 0
        else:
            pl, fundSource = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('整数', 123),
            ('浮点数', 12.3),
            ('布尔值', True),
            ('数组', [1, 2, 3]),
            ('对象', {'key': 'value'}),
            ('特殊字符', '!@#$%^&*()'),
            ('邮箱格式', 'test@example.com'),
            ('手机号格式', '13800138000'),
            ('日期格式', '2023-12-25'),
            ('表情符号', '😀🎉🚀'),
            ('超长字符串', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode字符', '中文测试'),
            ('JSON字符串', '{"key": "value"}'),
            ('XML字符串', '<root><item>test</item></root>'),
            ('URL字符串', 'https://www.example.com'),
            ('Base64字符串', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_createdonateorder_fundSource(self, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(fundSource)"""
        res = self.donate.createdonateorder(self.authorization, fundSource=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('最短长度', ""),
            ('最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_fundSource(self, desc, value):
        """创建捐赠订单-边界值测试-{desc}(fundSource)"""
        res = self.donate.createdonateorder(self.authorization, fundSource=value)
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_message(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(message)"""
        if desc == 'missing':
            pl, message = {'pop_items': 'message'}, 0
        else:
            pl, message = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('整数', 123),
            ('浮点数', 12.3),
            ('布尔值', True),
            ('数组', [1, 2, 3]),
            ('对象', {'key': 'value'}),
            ('特殊字符', '!@#$%^&*()'),
            ('邮箱格式', 'test@example.com'),
            ('手机号格式', '13800138000'),
            ('日期格式', '2023-12-25'),
            ('表情符号', '😀🎉🚀'),
            ('超长字符串', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode字符', '中文测试'),
            ('JSON字符串', '{"key": "value"}'),
            ('XML字符串', '<root><item>test</item></root>'),
            ('URL字符串', 'https://www.example.com'),
            ('Base64字符串', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_createdonateorder_message(self, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(message)"""
        res = self.donate.createdonateorder(self.authorization, message=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('最短长度', ""),
            ('最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_message(self, desc, value):
        """创建捐赠订单-边界值测试-{desc}(message)"""
        res = self.donate.createdonateorder(self.authorization, message=value)
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_platform(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(platform)"""
        if desc == 'missing':
            pl, platform = {'pop_items': 'platform'}, 0
        else:
            pl, platform = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('整数', 123),
            ('浮点数', 12.3),
            ('布尔值', True),
            ('数组', [1, 2, 3]),
            ('对象', {'key': 'value'}),
            ('特殊字符', '!@#$%^&*()'),
            ('邮箱格式', 'test@example.com'),
            ('手机号格式', '13800138000'),
            ('日期格式', '2023-12-25'),
            ('表情符号', '😀🎉🚀'),
            ('超长字符串', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode字符', '中文测试'),
            ('JSON字符串', '{"key": "value"}'),
            ('XML字符串', '<root><item>test</item></root>'),
            ('URL字符串', 'https://www.example.com'),
            ('Base64字符串', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_createdonateorder_platform(self, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(platform)"""
        res = self.donate.createdonateorder(self.authorization, platform=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('最短长度', ""),
            ('最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_platform(self, desc, value):
        """创建捐赠订单-边界值测试-{desc}(platform)"""
        res = self.donate.createdonateorder(self.authorization, platform=value)
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_donateChannel(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(donateChannel)"""
        if desc == 'missing':
            pl, donateChannel = {'pop_items': 'donateChannel'}, 0
        else:
            pl, donateChannel = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('整数', 123),
            ('浮点数', 12.3),
            ('布尔值', True),
            ('数组', [1, 2, 3]),
            ('对象', {'key': 'value'}),
            ('特殊字符', '!@#$%^&*()'),
            ('邮箱格式', 'test@example.com'),
            ('手机号格式', '13800138000'),
            ('日期格式', '2023-12-25'),
            ('表情符号', '😀🎉🚀'),
            ('超长字符串', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode字符', '中文测试'),
            ('JSON字符串', '{"key": "value"}'),
            ('XML字符串', '<root><item>test</item></root>'),
            ('URL字符串', 'https://www.example.com'),
            ('Base64字符串', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_createdonateorder_donateChannel(self, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(donateChannel)"""
        res = self.donate.createdonateorder(self.authorization, donateChannel=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('最短长度', ""),
            ('最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_donateChannel(self, desc, value):
        """创建捐赠订单-边界值测试-{desc}(donateChannel)"""
        res = self.donate.createdonateorder(self.authorization, donateChannel=value)
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_networkType(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(networkType)"""
        if desc == 'missing':
            pl, networkType = {'pop_items': 'networkType'}, 0
        else:
            pl, networkType = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('整数', 123),
            ('浮点数', 12.3),
            ('布尔值', True),
            ('数组', [1, 2, 3]),
            ('对象', {'key': 'value'}),
            ('特殊字符', '!@#$%^&*()'),
            ('邮箱格式', 'test@example.com'),
            ('手机号格式', '13800138000'),
            ('日期格式', '2023-12-25'),
            ('表情符号', '😀🎉🚀'),
            ('超长字符串', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode字符', '中文测试'),
            ('JSON字符串', '{"key": "value"}'),
            ('XML字符串', '<root><item>test</item></root>'),
            ('URL字符串', 'https://www.example.com'),
            ('Base64字符串', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_createdonateorder_networkType(self, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(networkType)"""
        res = self.donate.createdonateorder(self.authorization, networkType=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('最短长度', ""),
            ('最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_networkType(self, desc, value):
        """创建捐赠订单-边界值测试-{desc}(networkType)"""
        res = self.donate.createdonateorder(self.authorization, networkType=value)
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('缺失',  'missing'),
            ('为空', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_createdonateorder_transactionId(self, desc, value):
        """创建捐赠订单-必填字段测试-{desc}(transactionId)"""
        if desc == 'missing':
            pl, transactionId = {'pop_items': 'transactionId'}, 0
        else:
            pl, transactionId = {}, value
        res = self.donate.createdonateorder(**pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('整数', 123),
            ('浮点数', 12.3),
            ('布尔值', True),
            ('数组', [1, 2, 3]),
            ('对象', {'key': 'value'}),
            ('特殊字符', '!@#$%^&*()'),
            ('邮箱格式', 'test@example.com'),
            ('手机号格式', '13800138000'),
            ('日期格式', '2023-12-25'),
            ('表情符号', '😀🎉🚀'),
            ('超长字符串', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode字符', '中文测试'),
            ('JSON字符串', '{"key": "value"}'),
            ('XML字符串', '<root><item>test</item></root>'),
            ('URL字符串', 'https://www.example.com'),
            ('Base64字符串', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_createdonateorder_transactionId(self, desc, value):
        """创建捐赠订单-数据格式测试-{desc}(transactionId)"""
        res = self.donate.createdonateorder(self.authorization, transactionId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('最短长度', ""),
            ('最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_createdonateorder_transactionId(self, desc, value):
        """创建捐赠订单-边界值测试-{desc}(transactionId)"""
        res = self.donate.createdonateorder(self.authorization, transactionId=value)
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
        res = self.donate.createdonateorder(**test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'


    @pytest.mark.release
    def test_donate_positive_getNetworkCurrencyMapping_ok(self):
        """获取网络和币种对应关系-正向用例"""
        res = self.donate.getNetworkCurrencyMapping(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data'] == {'defaultCurrency': 'USDT', 'defaultNetwork': 'BNB Chain', 'networks': {'BNB Chain': {'chainId': 56, 'code': 'BSC', 'currencies': [{'address': '0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4', 'symbol': 'USDT'}, {'address': '0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4', 'symbol': 'USDC'}, {'address': '0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4', 'symbol': 'BNB'}, {'address': '0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4', 'symbol': 'ETH'}]}}}


    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthoried', 'missing'),
            ('empty', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_donate_permission_getNetworkCurrencyMapping(self, desc, value):
        """获取网络和币种对应关系-{desc}"""
        res = self.donate.getNetworkCurrencyMapping(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data'] == {'defaultCurrency': 'USDT', 'defaultNetwork': 'BNB Chain', 'networks': {'BNB Chain': {'chainId': 56, 'code': 'BSC', 'currencies': [{'address': '0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4', 'symbol': 'USDT'}, {'address': '0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4', 'symbol': 'USDC'}, {'address': '0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4', 'symbol': 'BNB'}, {'address': '0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4', 'symbol': 'ETH'}]}}}


    @pytest.mark.release
    def test_donate_positive_getPaymentAddress_ok(self):
        """获取支付地址-正向用例"""
        res = self.donate.getPaymentAddress(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['address']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unautorized', 'missing'),
            ('empty', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_donate_permission_getPaymentAddress(self, desc, value):
        """获取支付地址-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.donate.getPaymentAddress(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['address']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('lock',  'missing'),
            ('empty', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_getPaymentAddress_currency(self, desc, value):
        """获取支付地址-必填字段测试-{desc}(currency)"""
        if desc == 'missing':
            pl, currency = {'pop_items': 'currency'}, ''
        else:
            pl, currency = {}, value
        res = self.donate.getPaymentAddress(**pl, currency=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['address']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('Integer', 123),
            ('Float', 12.3),
            ('Boolean', True),
            ('Array', [1, 2, 3]),
            ('Object', {'key': 'value'}),
            ('Special characters', '!@#$%^&*()'),
            ('Email format', 'test@example.com'),
            ('Phone number format', '13800138000'),
            ('Date format', '2023-12-25'),
            ('Emoji', '😀🎉🚀'),
            ('Very long string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode characters', '中文测试'),
            ('JSON', '{"key": "value"}'),
            ('XML', '<root><item>test</item></root>'),
            ('URL', 'https://www.example.com'),
            ('Base64', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_getPaymentAddress_currency(self, desc, value):
        """获取支付地址-数据格式测试-{desc}(currency)"""
        res = self.donate.getPaymentAddress(currency=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert False

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('Minimum length', ""),
            ('Maximum length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_getPaymentAddress_currency(self, desc, value):
        """获取支付地址-边界值测试-{desc}(currency)"""
        res = self.donate.getPaymentAddress(self.authorization, currency=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert not res['data']['address']


    @pytest.mark.release
    def test_donate_scenario_getPaymentAddress_invalid_currency(self):
        """获取支付地址-场景异常-无效的currency"""
        test_params = {}
        test_params['currency'] = 'INVALID_VALUE'
        test_params['networkType'] = 'ETH'
        res = self.donate.getPaymentAddress(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert not res['data']['address']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('lock',  'missing'),
            ('empty', "''"),
            ('None', None),
        ]
    )
    def test_donate_required_getPaymentAddress_networkType(self, desc, value):
        """获取支付地址-必填字段测试-{desc}(networkType)"""
        if desc == 'missing':
            pl, networkType = {'pop_items': 'networkType'}, ''
        else:
            pl, networkType = {}, value
        res = self.donate.getPaymentAddress(networkType=value, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert not res['data']['address']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('Integer', 123),
            ('Float', 12.3),
            ('Boolean', True),
            ('Array', [1, 2, 3]),
            ('Object', {'key': 'value'}),
            ('Special characters', '!@#$%^&*()'),
            ('Email format', 'test@example.com'),
            ('Phone number format', '13800138000'),
            ('Date format', '2023-12-25'),
            ('Emoji', '😀🎉🚀'),
            ('Very long string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('Unicode characters', '中文测试'),
            ('JSON', '{"key": "value"}'),
            ('XML', '<root><item>test</item></root>'),
            ('URL', 'https://www.example.com'),
            ('Base64', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_getPaymentAddress_networkType(self, desc, value):
        """获取支付地址-数据格式测试-{desc}(networkType)"""
        res = self.donate.getPaymentAddress(self.authorization, networkType=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('Minimum length', ""),
            ('Maximum length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_getPaymentAddress_networkType(self, desc, value):
        """获取支付地址-边界值测试-{desc}(networkType)"""
        res = self.donate.getPaymentAddress(networkType=value)
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert not res['data']['address']

    @pytest.mark.release
    def test_donate_scenario_getPaymentAddress_invalid_networkType(self):
        """获取支付地址-场景异常-无效的networkType"""
        test_params = {}
        test_params['currency'] = 'Minimum length'
        test_params['networkType'] = 'INVALID_VALUE'
        res = self.donate.getPaymentAddress(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert not res['data']['address']

    @pytest.mark.release
    def test_donate_positive_getExchangeRate_ok(self):
        """获取汇率信息-正向用例"""
        res = self.donate.getExchangeRate(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

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
    def test_donate_permission_getExchangeRate(self, desc, value):
        """获取汇率信息-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.donate.getExchangeRate(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.release
    def test_donate_positive_getWithdrawLimit_ok(self):
        """获取限额信息-正向用例"""
        res = self.donate.getWithdrawLimit(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

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
    def test_donate_permission_getWithdrawLimit(self, desc, value):
        """获取限额信息-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.donate.getWithdrawLimit(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_donate_required_getWithdrawLimit_coin(self, desc, value):
        """获取限额信息-必填字段测试-{desc}(coin)"""
        if desc == 'missing':
            pl, coin = {'pop_items': 'coin'}, ''
        else:
            pl, coin = {}, value
        res = self.donate.getWithdrawLimit(coin=coin, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert False

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),
            ('float', 12.3),
            ('boolean', True),
            ('array', [1, 2, 3]),
            ('object', {'key': 'value'}),
            ('special_chars', '!@#$%^&*()'),
            ('email_format', 'test@example.com'),
            ('phone_format', '13800138000'),
            ('date_format', '2023-12-25'),
            ('emoji', '😀🎉🚀'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '中文测试'),
            ('json_string', '{"key": "value"}'),
            ('xml_string', '<root><item>test</item></root>'),
            ('url_string', 'https://www.example.com'),
            ('base64_string', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_getWithdrawLimit_coin(self, desc, value):
        """获取限额信息-数据格式测试-{desc}(coin)"""
        res = self.donate.getWithdrawLimit(self.authorization, coin=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert False

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_getWithdrawLimit_coin(self, desc, value):
        """获取限额信息-边界值测试-{desc}(coin)"""
        res = self.donate.getWithdrawLimit(self.authorization, coin=value)
    @pytest.mark.release
    def test_donate_scenario_getWithdrawLimit_invalid_coin(self):
        """获取限额信息-场景异常-无效的coin"""
        test_params = {}
        test_params['coin'] = 'INVALID_VALUE'
        test_params['network'] = ''
        res = self.donate.getWithdrawLimit(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_donate_required_getWithdrawLimit_network(self, desc, value):
        """获取限额信息-必填字段测试-{desc}(network)"""
        if desc == 'missing':
            pl, network = {'pop_items': 'network'}, ''
        else:
            pl, network = {}, value
        res = self.donate.getWithdrawLimit(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),
            ('float', 12.3),
            ('boolean', True),
            ('array', [1, 2, 3]),
            ('object', {'key': 'value'}),
            ('special_chars', '!@#$%^&*()'),
            ('email_format', 'test@example.com'),
            ('phone_format', '13800138000'),
            ('date_format', '2023-12-25'),
            ('emoji', '😀🎉🚀'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '中文测试'),
            ('json_string', '{"key": "value"}'),
            ('xml_string', '<root><item>test</item></root>'),
            ('url_string', 'https://www.example.com'),
            ('base64_string', 'SGVsbG8gV29ybGQ='),
        ]
    )
    def test_donate_format_getWithdrawLimit_network(self, desc, value):
        """获取限额信息-数据格式测试-{desc}(network)"""
        res = self.donate.getWithdrawLimit(self.authorization, network=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_donate_boundary_getWithdrawLimit_network(self, desc, value):
        """获取限额信息-边界值测试-{desc}(network)"""
        res = self.donate.getWithdrawLimit(self.authorization, network=value)
    @pytest.mark.release
    def test_donate_scenario_getWithdrawLimit_invalid_network(self):
        """获取限额信息-场景异常-无效的network"""
        test_params = {}
        test_params['coin'] = ''
        test_params['network'] = 'INVALID_VALUE'
        res = self.donate.getWithdrawLimit(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
        ]
    )
    def test_donate_security_getWithdrawLimit_network(self, test_type, test_desc, attack_value):
        """获取限额信息-安全测试-{test_desc}(network)"""
        test_params = {}
        test_params['coin'] = ''
        test_params['network'] = attack_value
        res = self.donate.getWithdrawLimit(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_donate_positive_cancel_ok(self):
        """取消捐赠订单-正向用例"""
        res = self.donate.cancel(self.authorization, **{})
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

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
    def test_donate_permission_cancel(self, desc, value):
        """取消捐赠订单-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.donate.cancel(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_donate_required_cancel_orderId(self, desc, value):
        """取消捐赠订单-必填字段测试-{desc}(orderId)"""
        if desc == 'missing':
            pl, orderId = {'pop_items': 'orderId'}, 0
        else:
            pl, orderId = {}, value
        res = self.donate.cancel(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', '字符串', '"abc"'),
            ('float', '浮点数', '12.34'),
            ('boolean', '布尔值', 'True'),
            ('array', '数组', '[1, 2, 3]'),
            ('object', '对象', '{"key": "value"}'),
            ('special_chars', '特殊字符', '"!@#$%^&*()"'),
            ('emoji', '表情符号', '"😀🎉🚀"'),
            ('long_string', '超长字符串', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_donate_format_cancel_orderId(self, desc, value):
        """取消捐赠订单-数据格式测试-{desc}(orderId)"""
        res = self.donate.cancel(self.authorization, orderId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_donate_boundary_cancel_orderId(self, desc, value):
        """取消捐赠订单-边界值测试-{desc}(orderId)"""
        res = self.donate.cancel(self.authorization, orderId=value)
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.release
    def test_donate_scenario_cancel_invalid_orderId(self):
        """取消捐赠订单-场景异常-无效的orderId"""
        test_params = {}
        res = self.donate.cancel(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.release
    def test_donate_positive_webhook_ok(self):
        """币安支付Webhook回调处理-正向用例"""
        res = self.donate.webhook(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

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
    def test_donate_permission_webhook(self, desc, value):
        """币安支付Webhook回调处理-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.donate.webhook(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

