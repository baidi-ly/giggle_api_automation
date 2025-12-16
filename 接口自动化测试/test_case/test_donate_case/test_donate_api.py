import pytest
import time

from test_case.page_api.donate.donate_api import DonateApi
from config import RunConfig

base_url = RunConfig.baseurl

@pytest.mark.donate
class TestDonateApi:
    """
    donate 接口测试用例
    """

    def setup_class(self):
        self.donate = DonateApi()
        self.authorization = self.donate.get_authorization()[0]

    @pytest.mark.smoke
    def test_donate_positive_createdonateorder_ok(self):
        """创建捐赠订单-正向用例"""
        res = self.donate.createdonateorder(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.smoke
    def test_donate_positive_getNetworkCurrencyMapping_ok(self):
        """获取网络和币种对应关系-正向用例"""
        res = self.donate.getNetworkCurrencyMapping(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']

    @pytest.mark.smoke
    def test_donate_positive_getPaymentAddress_ok(self):
        """获取支付地址-正向用例"""
        res = self.donate.getPaymentAddress(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['address']

    @pytest.mark.smoke
    def test_donate_positive_getExchangeRate_ok(self):
        """获取汇率信息-正向用例"""
        res = self.donate.getExchangeRate(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.smoke
    def test_donate_positive_getWithdrawLimit_ok(self):
        """获取限额信息-正向用例"""
        res = self.donate.getWithdrawLimit(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']

    @pytest.mark.smoke
    def test_donate_positive_cancel_ok(self):
        """取消捐赠订单-正向用例"""
        res = self.donate.cancel(self.authorization, code=200)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'
        assert res['code'] == 100121
        assert res['message'] == 'Order not found'
        assert res['data'] == 'Order not found'

    @pytest.mark.smoke
    def test_donate_positive_webhook_ok(self):
        """币安支付Webhook回调处理-正向用例"""
        requestBodyString = 'hello'
        res = self.donate.webhook(authorization=self.authorization, requestBodyString=requestBodyString)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.smoke
    def test_donate_positive_donateorderstatus_details_ok(self):
        """查询捐赠订单状态-正向用例"""
        res = self.donate.donateorderstatus_details(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100121, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        # assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        # assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_donate_positive_getOrders_ok(self):
        """分页获取捐赠订单列表-正向用例"""
        res = self.donate.getOrders(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
