import json
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
DeviceId = RunConfig.DeviceId


class RewardApi(BaseAPI):
    """奖励接口"""

    def continuousProgress(self, authorization, kidsId, DeviceType="web", code=200):
        """
        连续学习进度
        :param kidsId: (integer, path, required) kidsId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-02
        url = f"https://{base_url}/api/reward/getContinuousProgress/{kidsId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "连续学习进度"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

