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

