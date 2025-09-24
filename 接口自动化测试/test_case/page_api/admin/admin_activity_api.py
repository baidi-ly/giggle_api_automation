
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminActivityApi(BaseAPI):
    """活动接口"""

    def create(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        创建活动
        :param name: (string, body, required) name 参数
        :param activityCode: (string, body, required) activityCode 参数
        :param startTime: (string, body, required) startTime 参数
        :param endTime: (string, body, required) endTime 参数
        :param config: (object, body, required) config 参数
        :param status: (string, body, required) status 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/admin/activity/create"
        payload = {
            "name": "扭蛋抽奖活动",
            "activityCode": "GACHA_2024",
            "startTime": "2024-12-01T08:00:00",
            "endTime": "2024-12-31T23:59:59",
            "config": {
                "defaultDraws": 1,
                "shareMax": 2,
                "normalStickerProbability": 0.7,
                "pointsProbability": 0.3
            },
            "status": "ACTIVE"
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建活动"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

