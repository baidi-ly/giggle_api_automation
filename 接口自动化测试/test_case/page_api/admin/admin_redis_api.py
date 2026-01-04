import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
admin_base_url = BaseAPI().admin_baseurl()


class AdminRedisApi(BaseAPI):
    '''redis api'''

    def redisHash(self, authorization, key='', DeviceType="web"):
        """
        获取Redis Hash的所有数据
        :param key: (string, query, required) Redis hash key
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{admin_base_url}/admin/redis/hash"
        payload = {
            "key": key
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取Redis Hash的所有数据"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def deleteHashField(self, authorization, field='', key='', DeviceType="web"):
        """
        删除Redis Hash的指定field
        :param field: (string, query, required) Hash field
        :param key: (string, query, required) Redis hash key
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{admin_base_url}/admin/redis/hash/field"
        payload = {
            "field": field,
            "key": key
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers, params=payload)
        error_msg = "删除Redis Hash的指定field"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def setUserGrayscale(self, authorization, DeviceType="web", **kwargs):
        """
        设置单个灰度用户（写入到 feature 对应的 hash）
        :param field: (string, query, required) Hash field
        :param key: (string, query, required) Redis hash key
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/grayscale/user/set"
        payload = {
            "feature": "",
            "userKey": "",
            "enabled": True
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "设置单个灰度用户（写入到 feature 对应的 hash）"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def setGrayscalePercentage(self, authorization, DeviceType="web", **kwargs):
        """
        设置灰度配置百分比
        :param feature: 灰度功能标识（例如 dibo_test20251223150653）。
        :param percentage: 百分比，取值范围 0–100（表示灰度覆盖比例）。
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{admin_base_url}/admin/grayscale/config/percentage"
        payload = {
            "feature": "",
            "percentage": 50
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "设置灰度配置百分比"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response