
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminActivityApi(BaseAPI):
    """活动接口"""

    def getList(self, authorization, all=False, keyword='', page=0, size=10, status='', DeviceType="web", code=200, **kwargs):
        """
        获取活动列表
        :param all: (boolean, query, optional) all
        :param keyword: (string, query, optional) keyword
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param status: (string, query, optional) status
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/admin/activity/list"
        payload = {
            "all": all,
            "keyword": keyword,
            "page": page,
            "size": size,
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取活动列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

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
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/admin/activity/create"
        payload = {
            "name": "扭蛋抽奖活动",
            "activityCode": "GACHA_2024",
            "startTime": "",
            "endTime": "",
            "config": {
                "defaultDraws": 1,
                "shareMax": 2,
                "normalStickerProbability": 0.7,
                "pointsProbability": 0.3
            },
            "status": "ACTIVE"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建活动"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response