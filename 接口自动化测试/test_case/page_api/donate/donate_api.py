import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class DonateApi(BaseAPI):
    """孩子学习统计接口"""

    def createdonateorder(self, authorization, request='', DeviceType="web", code=200, **kwargs):
        """
        创建捐赠订单
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/donate/createDonateOrder"
        payload = {
            "request": request
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建捐赠订单"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

