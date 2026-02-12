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

        self.transactionId = '0x66711962a74056d7e6bd4dab7be5c03ec35b76ace90cc38e120b1d0e2087e8d8'

    @pytest.mark.smoke
    def test_donate_positive_createdonateorder_ok(self):
        """创建捐赠订单 - 需要真实交易无法验证正向流程 - 验证同一订单id无法重复创建"""
        res = self.donate.createdonateorder(self.authorization, transactionId=self.transactionId)
        assert res['code'] == 100126
        assert res['message'] == 'Transaction ID already exists'
        assert res['data'] == 'Transaction ID already exists'

    @pytest.mark.smoke
    def test_donate_positive_createdonateorder_notReal(self):
        """创建捐赠订单 - 需要真实交易无法验证正向流程 - 验证非真实的订单无法创建"""
        transactionId = '0x66711962a74056d7e6bd4dab7be5c03ec35b76ace90cc38e120b1d0e2087e8d9'
        res = self.donate.createdonateorder(self.authorization, transactionId=transactionId)
        assert res['code'] == 100128
        assert res['message'] == 'Transaction hash not found on blockchain'
        assert res['data'] == 'Transaction hash not found on blockchain'

    @pytest.mark.smoke
    def test_donate_positive_getNetworkCurrencyMapping_ok(self):
        """获取网络和币种对应关系"""
        res = self.donate.getNetworkCurrencyMapping(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        networkMapping = {
            "defaultCurrency": "USDT",
            "defaultNetwork": "BNB Chain",
            "networks": {
                "BNB Chain": {
                    "chainId": 56,
                    "code": "BSC",
                    "currencies": [
                        {
                            "address": "0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4",
                            "symbol": "USDT"
                        },
                        {
                            "address": "0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4",
                            "symbol": "USDC"
                        },
                        {
                            "address": "0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4",
                            "symbol": "BNB"
                        },
                        {
                            "address": "0xC7f501D25Ea088aeFCa8B4b3ebD936aAe12bF4A4",
                            "symbol": "ETH"
                        }
                    ]
                }
            }
        }
        assert res['data'] == networkMapping

    @pytest.mark.smoke
    def test_donate_positive_getPaymentAddress_ok(self):
        """获取支付地址"""
        res = self.donate.getPaymentAddress(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['address']

    @pytest.mark.smoke
    def test_donate_positive_getExchangeRate_ok(self):
        """获取汇率信息"""
        res = self.donate.getExchangeRate(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']['BHFT']
        assert res['data']['data']['BNB']
        assert res['data']['data']['BTC']
        assert res['data']['data']['BUSD']
        assert res['data']['data']['DOGE']
        assert res['data']['data']['ETH']
        assert res['data']['data']['PAX']
        assert res['data']['data']['PCAT']
        assert res['data']['data']['PPE']
        assert res['data']['data']['TREE']
        assert res['data']['data']['USDC']
        assert res['data']['data']['USDT']
        assert res['data']['data']['XRP']

    @pytest.mark.smoke
    def test_donate_positive_getWithdrawLimit_ok(self):
        """获取限额信息"""
        res = self.donate.getWithdrawLimit(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']

    @pytest.mark.smoke
    def test_donate_positive_cancelOrders_ok(self):
        """取消捐赠订单 - 正向用例必须满足订单真实存在且状态为pending的订单"""
        order_id = self.donate.donate_orders(self.authorization, size=5000)['data']['content'][0]['orderId']
        res = self.donate.cancelOrders(self.authorization, order_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'
        assert res['code'] == 100121
        assert res['message'] == 'Order not found'
        assert res['data'] == 'Order not found'

    @pytest.mark.smoke
    def test_donate_positive_webhook_ok(self):
        """币安支付Webhook回调处理"""
        requestBodyString = 'hello'
        res = self.donate.webhook(self.authorization, requestBodyString=requestBodyString)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200
        assert res['message'] == 'success'
        assert res['data']['data']

    @pytest.mark.smoke
    def test_donate_positive_donateorderstatus_details_ok(self):
        """查询捐赠订单状态"""
        orders_res = self.donate.donate_orders(self.authorization, size=5000)['data']['content']
        for order in orders_res:
            if order['transactionId'] == '0x0bbfc98654ad18ac7bd81d90ffa11b0c524c46395821e8ada2aa5f969d33eb74':
                order_id = order['orderId']
                break
        else:
            assert False, "未找到指定交易id的订单！"
        res = self.donate.donateorderstatus_details(self.authorization, order_id)
        order_info = {
            "amount": 0.00022232,
            "confirmDescription": None,
            "currency": "BNB",
            "name": "Anonymous Donor",
            "orderId": 752568142386693,
            "paymentStatus": "SUCCESS"
        }
        order_res = res['data']
        order_res.pop('createTime')
        assert res['data'] == order_info

    @pytest.mark.smoke
    def test_donate_positive_getList_ok(self):
        """分页查询支出记录列表-正向用例"""
        res = self.donate.getList(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
