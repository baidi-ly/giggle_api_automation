import json
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class DonateApi(BaseAPI):
    """孩子学习统计接口"""

    def createdonateorder(self, authorization='', DeviceType="web", code=200, **kwargs):
        """
        创建捐赠订单
        :param amount: (string, body, required) amount 参数
        :param donorName: (string, body, required) donorName 参数
        :param anonymous: (boolean, body, required) anonymous 参数
        :param currency: (string, body, required) currency 参数
        :param donorType: (string, body, required) donorType 参数
        :param donorEmailAddress: (string, body, required) donorEmailAddress 参数
        :param fundSource: (string, body, required) fundSource 参数
        :param message: (string, body, required) message 参数
        :param platform: (string, body, required) platform 参数
        :param donateChannel: (string, body, required) donateChannel 参数
        :param networkType: (string, body, required) networkType 参数
        :param transactionId: (string, body, required) transactionId 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/donate/createDonateOrder"
        payload = {
            "amount": "100.50",
            "donorName": "张三",
            "anonymous": False,
            "currency": "USDT",
            "donorType": "individual",
            "donorEmailAddress": "donor@example.com",
            "fundSource": "personal_savings",
            "message": "希望能帮助到更多的孩子",
            "platform": "WEB",
            "donateChannel": "binance_pay",
            "networkType": "BSC",
            "transactionId": "0x1234567890abcdef"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建捐赠订单"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getNetworkCurrencyMapping(self, authorization='', DeviceType="web", code=200, **kwargs):
        """
        获取网络和币种对应关系

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/donate/network-currency-mapping"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取网络和币种对应关系"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getPaymentAddress(self, authorization='', currency='USDT', networkType='ETH', DeviceType="web", code=200, **kwargs):
        """
        获取支付地址
        :param currency: (string, query, required) 币种
        :param networkType: (string, query, required) 网络类型
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/donate/payment-address"
        payload = {
            "currency": currency,
            "networkType": networkType
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取支付地址"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getExchangeRate(self, authorization='', DeviceType="web", code=200, **kwargs):
        """
        获取汇率信息

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/donate/exchange-rate"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取汇率信息"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getWithdrawLimit(self, authorization='', coin='USDT', network='ERC20', DeviceType="web", code=200, **kwargs):
        """
        获取限额信息
        :param coin: (string, query, required) 币种 USDT, USDC, BTC, ETH, BNB, BUSD
        :param network: (string, query, required) 网络 支持的网络: TRC20, ERC20, BTC, BSC
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/donate/withdraw-limit"
        payload = {
            "coin": coin,
            "network": network
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取限额信息"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def cancel(self, authorization='', orderId=0, DeviceType="web", code=200, **kwargs):
        """
        取消捐赠订单
        :param orderId: (integer, path, required) 订单ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/donate/orders/{orderId}/cancel"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "取消捐赠订单"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def webhook(self, authorization='', DeviceType="web", code=200, **kwargs):
        """
        币安支付Webhook回调处理
        :param
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/donate/orders/webhook"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "币安支付Webhook回调处理"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

