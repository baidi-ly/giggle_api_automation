import json
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class ActivityApi(BaseAPI):
    """孩子学习统计接口"""

    def getInfo(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取扭蛋当前活动信息

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/activity/gacha/info"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取扭蛋当前活动信息"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 401:
            response = response.json()
            return response

    def getInfo1(self, authorization, activityId=1, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        获取用户抽奖信息
        :param activityId: (integer, query, required) activityId
        :param kidId: (integer, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/activity/gacha/user/info"
        payload = {
            "activityId": activityId,
            "kidId": kidId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取用户抽奖信息"
        if code != 401:
            assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
            response = response.json()
            return response

